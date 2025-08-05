#!/bin/bash

# Neuron Release Package Script
# 用于打包完整的neuron发布版本

set -e

# 配置变量
PACKAGE_NAME="dmp-edge"
VERSION=$(cat version 2>/dev/null || echo "2.5.0")
ARCH=$(uname -m)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}开始打包 Neuron Release 版本...${NC}"
echo -e "${YELLOW}版本: ${VERSION}${NC}"
echo -e "${YELLOW}架构: ${ARCH}${NC}"

# 检查构建目录
if [ ! -f "build/neuron" ]; then
    echo -e "${RED}错误: 未找到构建文件，请先运行构建命令${NC}"
    echo "请执行: mkdir -p build && cd build && cmake .. && make"
    exit 1
fi

# 清理旧的打包目录
rm -rf ${PACKAGE_NAME}
mkdir -p ${PACKAGE_NAME}

echo -e "${GREEN}创建目录结构...${NC}"

# 创建目录结构
mkdir -p ${PACKAGE_NAME}/bin
mkdir -p ${PACKAGE_NAME}/lib
mkdir -p ${PACKAGE_NAME}/config
mkdir -p ${PACKAGE_NAME}/plugins
mkdir -p ${PACKAGE_NAME}/plugins/schema
mkdir -p ${PACKAGE_NAME}/logs
mkdir -p ${PACKAGE_NAME}/persistence
mkdir -p ${PACKAGE_NAME}/dist

echo -e "${GREEN}复制可执行文件...${NC}"

# 复制可执行文件和库文件
cp build/neuron ${PACKAGE_NAME}/bin/
cp build/libneuron-base.so ${PACKAGE_NAME}/lib/

# 复制依赖库
echo -e "${GREEN}复制系统依赖库...${NC}"

# 复制存在的依赖库
for lib in "/usr/local/lib/libzlog.so.1.2" "/usr/local/lib/libopen62541.so.1.4" "/usr/local/lib/libnng.so" "/usr/local/lib/libjansson.so" "/usr/local/lib/libxml2.so" "/usr/local/lib/libssl.so" "/usr/local/lib/libcrypto.so" "/usr/local/lib/libmbedtls.so" "/usr/local/lib/libmbedx509.so" "/usr/local/lib/libmbedcrypto.so"; do
    if [ -f "$lib" ]; then
        cp "$lib" ${PACKAGE_NAME}/lib/
        echo "  ✓ 复制: $(basename $lib)"
    else
        echo -e "${YELLOW}  ⚠  未找到: $(basename $lib)${NC}"
    fi
done

# 复制符号链接
if [ -L "/usr/local/lib/libopen62541.so" ]; then
    cp -P /usr/local/lib/libopen62541.so ${PACKAGE_NAME}/lib/
    echo "  ✓ 复制符号链接: libopen62541.so"
fi

echo -e "${GREEN}复制配置文件...${NC}"

# 复制配置文件
cp build/config/* ${PACKAGE_NAME}/config/
cp neuron.conf ${PACKAGE_NAME}/
cp default_plugins.json ${PACKAGE_NAME}/config/

echo -e "${GREEN}复制插件文件...${NC}"

# 复制插件文件
cp build/plugins/libplugin-*.so ${PACKAGE_NAME}/plugins/ 2>/dev/null || true

# 复制插件配置文件
echo -e "${GREEN}复制插件配置文件...${NC}"
cp build/plugins/schema/*.json ${PACKAGE_NAME}/plugins/schema/ 2>/dev/null || true

echo -e "${GREEN}复制Web界面...${NC}"

# 复制Web界面（如果存在）
if [ -d "build/dist" ]; then
    cp -r build/dist/* ${PACKAGE_NAME}/dist/
    echo "  ✓ 复制build/dist中的Web文件"
fi

# 如果neuron-dashboard已构建，也复制过来
if [ -d "../neuron-dashboard/dist" ]; then
    echo -e "${YELLOW}发现neuron-dashboard构建文件，正在复制...${NC}"
    cp -r ../neuron-dashboard/dist/* ${PACKAGE_NAME}/dist/
    echo "  ✓ 复制neuron-dashboard/dist中的Web文件"
fi

echo -e "${GREEN}创建启动脚本...${NC}"

# 创建启动脚本
cat > ${PACKAGE_NAME}/start.sh << 'EOF'
#!/bin/bash

# Neuron 启动脚本
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 设置环境变量
export LD_LIBRARY_PATH="$SCRIPT_DIR/lib:$LD_LIBRARY_PATH"

# 创建必要的目录
mkdir -p logs
mkdir -p persistence

# 检查关键依赖库
echo "检查依赖库..."
for lib in libneuron-base.so libzlog.so.1.2 libopen62541.so; do
    if [ -f "./lib/$lib" ]; then
        echo "  ✓ 找到: $lib"
    else
        echo "  ⚠  警告: 未找到 $lib"
    fi
done

# 启动neuron
echo "启动 Neuron..."
echo "库路径: $LD_LIBRARY_PATH"
./bin/neuron
EOF

chmod +x ${PACKAGE_NAME}/start.sh

# 创建停止脚本
cat > ${PACKAGE_NAME}/stop.sh << 'EOF'
#!/bin/bash

# Neuron 停止脚本
echo "停止 Neuron..."
pkill -f "neuron" || true
echo "Neuron 已停止"
EOF

chmod +x ${PACKAGE_NAME}/stop.sh

# 创建README文件
cat > ${PACKAGE_NAME}/README.txt << EOF
Neuron Release Package
======================

版本: ${VERSION}
架构: ${ARCH}
打包时间: ${TIMESTAMP}

使用方法:
1. 解压到目标目录
2. 运行 ./start.sh 启动服务
3. 运行 ./stop.sh 停止服务
4. 访问 http://localhost:7000 打开Web界面

配置文件位置:
- 主配置: config/neuron.json
- 日志配置: config/zlog.conf
- 插件配置: config/default_plugins.json

日志文件位置:
- logs/ 目录

数据文件位置:
- persistence/ 目录

注意事项:
- 确保目标系统有必要的依赖库
- 首次运行会自动创建数据库文件
- 可以通过修改配置文件调整服务参数
EOF

echo -e "${GREEN}创建压缩包...${NC}"

# 创建压缩包
tar czf ${PACKAGE_NAME}-${VERSION}-${ARCH}-${TIMESTAMP}.tar.gz ${PACKAGE_NAME}/

echo -e "${GREEN}清理临时文件...${NC}"
rm -rf ${PACKAGE_NAME}

echo -e "${GREEN}打包完成!${NC}"
echo -e "${GREEN}发布包: ${PACKAGE_NAME}-${VERSION}-${ARCH}-${TIMESTAMP}.tar.gz${NC}"
echo -e "${YELLOW}文件大小: $(du -h ${PACKAGE_NAME}-${VERSION}-${ARCH}-${TIMESTAMP}.tar.gz | cut -f1)${NC}" 
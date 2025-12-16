#!/bin/bash

# 测试 DKG 协议生成文件脚本
# 测试 GG18、GG20、FROST 协议是否能生成两个文件（.enc 和 .keydata.enc）

set -e

PROJECT_DIR="/Users/caimin/Desktop/kms/go-mpc-wallet"
cd "$PROJECT_DIR"

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== DKG 协议文件生成测试 ===${NC}\n"

# 测试函数
test_protocol() {
    local protocol=$1
    echo -e "${YELLOW}测试协议: $protocol${NC}"
    
    # 修改 docker-compose.yml 中的 MPC_DEFAULT_PROTOCOL
    echo "修改 docker-compose.yml 中的 MPC_DEFAULT_PROTOCOL 为 $protocol..."
    sed -i.bak "s/MPC_DEFAULT_PROTOCOL: \".*\"/MPC_DEFAULT_PROTOCOL: \"$protocol\"/g" docker-compose.yml
    
    # 重启所有节点
    echo "重启所有节点..."
    docker compose restart coordinator participant-1 participant-2 participant-3
    
    # 等待节点启动
    echo "等待节点启动..."
    sleep 15
    
    # 检查节点状态
    echo "检查节点状态..."
    docker compose ps | grep -E "(coordinator|participant)" | grep -v "starting"
    
    # 获取访问令牌（简化版，直接使用第一个）
    TOKEN=$(docker compose exec -T postgres psql -U dbuser -d mpc-dev-db -t -A -c "SELECT token FROM access_tokens LIMIT 1;" 2>&1 | head -1 | tr -d ' ')
    
    if [ -z "$TOKEN" ]; then
        echo -e "${RED}无法获取访问令牌，跳过 API 测试${NC}"
        return 1
    fi
    
    echo "使用令牌: ${TOKEN:0:20}..."
    
    # 创建密钥（触发 DKG）
    echo "创建密钥（触发 DKG）..."
    KEY_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/mpc/keys \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "algorithm": "ECDSA",
            "curve": "secp256k1",
            "threshold": 2,
            "total_nodes": 3,
            "chain_type": "ethereum"
        }')
    
    KEY_ID=$(echo "$KEY_RESPONSE" | jq -r '.key_id // empty' 2>/dev/null || echo "")
    
    if [ -z "$KEY_ID" ]; then
        echo -e "${RED}创建密钥失败: $KEY_RESPONSE${NC}"
        return 1
    fi
    
    echo "密钥 ID: $KEY_ID"
    
    # 等待 DKG 完成（最多等待 60 秒）
    echo "等待 DKG 完成..."
    for i in {1..60}; do
        sleep 1
        STATUS=$(docker compose exec -T postgres psql -U dbuser -d mpc-dev-db -t -A -c "SELECT status FROM keys WHERE key_id = '$KEY_ID';" 2>&1 | head -1 | tr -d ' ')
        if [ "$STATUS" = "Active" ]; then
            echo "DKG 完成，密钥状态: $STATUS"
            break
        fi
        if [ $i -eq 60 ]; then
            echo -e "${RED}DKG 超时（60秒）${NC}"
            return 1
        fi
    done
    
    # 检查文件生成
    echo "检查文件生成..."
    sleep 2
    
    # 检查 participant-1 的文件
    ENC_FILE=$(docker compose exec participant-1 ls -1 /app/var/lib/mpc/key-shares/$KEY_ID/participant-1.enc 2>/dev/null || echo "")
    KEYDATA_FILE=$(docker compose exec participant-1 ls -1 /app/var/lib/mpc/key-shares/$KEY_ID/participant-1.keydata.enc 2>/dev/null || echo "")
    
    if [ -n "$ENC_FILE" ] && [ -n "$KEYDATA_FILE" ]; then
        echo -e "${GREEN}✓ 协议 $protocol: 两个文件都已生成${NC}"
        echo "  - participant-1.enc: $(docker compose exec participant-1 ls -lh /app/var/lib/mpc/key-shares/$KEY_ID/participant-1.enc 2>/dev/null | awk '{print $5}')"
        echo "  - participant-1.keydata.enc: $(docker compose exec participant-1 ls -lh /app/var/lib/mpc/key-shares/$KEY_ID/participant-1.keydata.enc 2>/dev/null | awk '{print $5}')"
        return 0
    else
        echo -e "${RED}✗ 协议 $protocol: 文件生成失败${NC}"
        if [ -z "$ENC_FILE" ]; then
            echo "  - participant-1.enc: 缺失"
        else
            echo "  - participant-1.enc: 存在"
        fi
        if [ -z "$KEYDATA_FILE" ]; then
            echo "  - participant-1.keydata.enc: 缺失"
        else
            echo "  - participant-1.keydata.enc: 存在"
        fi
        return 1
    fi
}

# 测试所有协议
PROTOCOLS=("frost" "gg18" "gg20")
RESULTS=()

for protocol in "${PROTOCOLS[@]}"; do
    echo ""
    if test_protocol "$protocol"; then
        RESULTS+=("$protocol: ✓")
    else
        RESULTS+=("$protocol: ✗")
    fi
    echo ""
    sleep 5
done

# 恢复原始配置
echo "恢复原始配置..."
if [ -f docker-compose.yml.bak ]; then
    mv docker-compose.yml.bak docker-compose.yml
fi

# 重启节点
docker compose restart coordinator participant-1 participant-2 participant-3

# 输出结果摘要
echo ""
echo -e "${YELLOW}=== 测试结果摘要 ===${NC}"
for result in "${RESULTS[@]}"; do
    if [[ $result == *"✓"* ]]; then
        echo -e "${GREEN}$result${NC}"
    else
        echo -e "${RED}$result${NC}"
    fi
done

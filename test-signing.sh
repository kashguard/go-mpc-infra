#!/bin/bash
# 签名测试脚本
# 使用方法：./test-signing.sh <key_id> <message_base64>

KEY_ID=${1:-"key-26cdb9c7-0af9-456f-8690-5a526554dcb0"}
MESSAGE=${2:-"SGVsbG8gV29ybGQ="}  # "Hello World" in base64

echo "=== 签名测试 ==="
echo "Key ID: $KEY_ID"
echo "Message (base64): $MESSAGE"
echo ""

# 注意：需要提供认证token
# TOKEN="your-auth-token"
# curl -X POST http://localhost:8080/api/v1/mpc/sign \
#   -H "Authorization: Bearer $TOKEN" \
#   -H "Content-Type: application/json" \
#   -d "{
#     \"key_id\": \"$KEY_ID\",
#     \"message\": \"$MESSAGE\",
#     \"message_type\": \"raw\",
#     \"chain_type\": \"ethereum\"
#   }"

echo "请手动执行签名API调用，或提供认证token后取消注释上面的curl命令"
echo ""
echo "监控日志命令："
echo "docker compose logs -f participant-1 participant-2 participant-3 | grep -E '(DIAGNOSTIC|executeSigning|ProcessIncomingSigningMessage|total_messages_processed|Signing timeout|signature)'"

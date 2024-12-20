import os

# 生成16字节(128位)的随机密钥
key = os.urandom(16)

# 如果需要查看十六进制格式
hex_key = key.hex()
print(hex_key)
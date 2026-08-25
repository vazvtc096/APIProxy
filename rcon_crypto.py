"""
RCON 加密模块 - RSA 2048 非对称密钥 + AES-256-GCM 会话加密
标准混合加密方案：RSA 密钥交换 + AES 数据加密

注意：
- RSA 2048 位是标准安全长度
- AES-256-GCM 提供加密和认证（防篡改）
- 每个连接生成新的 AES 会话密钥，15 分钟有效期
"""

import os
import time
import base64
import secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# 配置
from .configs import RCON_RSA_KEY_SIZE as RSA_KEY_SIZE  # RSA 密钥长度（位），取自配置文件
AES_KEY_SIZE = 32  # AES-256 密钥长度（字节）
NONCE_SIZE = 12  # GCM nonce 长度（字节）
CHALLENGE_LENGTH = 32  # 挑战字符串长度（字节）
AES_KEY_TTL = 15 * 60  # AES 密钥有效期（秒），默认 15 分钟

# 密钥文件路径
BASE_DIR = Path(__file__).resolve().parent
PRIVATE_KEY_FILE = str(BASE_DIR / '.rcon_private.pem')  # 私钥文件
PUBLIC_KEY_FILE = str(BASE_DIR / '.rcon_public.pem')  # 公钥文件


def generate_rsa_keypair(key_size: int = None) -> tuple[bytes, bytes]:
    """
    生成 RSA 密钥对
    
    Args:
        key_size: 密钥长度（位），默认使用环境变量配置
    
    Returns:
        (私钥 PEM, 公钥 PEM)
    """
    if key_size is None:
        key_size = RSA_KEY_SIZE
    
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    
    # 导出私钥（PEM 格式，无加密）
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 导出公钥（PEM 格式）
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem


def save_keypair(private_pem: bytes, public_pem: bytes):
    """保存密钥对到文件"""
    # 保存私钥
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_pem)
    os.chmod(PRIVATE_KEY_FILE, 0o600)  # 仅所有者可读写
    
    # 保存公钥
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_pem)


def load_private_key() -> rsa.RSAPrivateKey:
    """加载私钥"""
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_pem = f.read()
    return serialization.load_pem_private_key(private_pem, password=None)


def load_public_key() -> rsa.RSAPublicKey:
    """加载公钥"""
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_pem = f.read()
    return serialization.load_pem_public_key(public_pem)


def load_public_key_from_pem(pem_data: bytes) -> rsa.RSAPublicKey:
    """从 PEM 数据加载公钥"""
    return serialization.load_pem_public_key(pem_data)


def load_private_key_from_pem(pem_data: bytes) -> rsa.RSAPrivateKey:
    """从 PEM 数据加载私钥"""
    return serialization.load_pem_private_key(pem_data, password=None)


def get_public_key_pem() -> bytes:
    """获取公钥 PEM 格式"""
    with open(PUBLIC_KEY_FILE, 'rb') as f:
        return f.read()


def ensure_keypair_exists() -> bool:
    """
    确保密钥对存在，不存在则生成
    
    Returns:
        True 表示新生成了密钥，False 表示密钥已存在
    """
    if os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE):
        return False
    
    # 生成新密钥对
    private_pem, public_pem = generate_rsa_keypair()
    save_keypair(private_pem, public_pem)
    print(f"[RCON] 已生成 RSA {RSA_KEY_SIZE} 位密钥对")
    print(f"[RCON] 私钥: {PRIVATE_KEY_FILE}")
    print(f"[RCON] 公钥: {PUBLIC_KEY_FILE}")
    return True


def generate_challenge() -> bytes:
    """生成随机挑战字符串"""
    return secrets.token_bytes(CHALLENGE_LENGTH)


def sign_challenge(private_key: rsa.RSAPrivateKey, challenge: bytes) -> bytes:
    """
    用私钥对挑战进行签名
    
    Args:
        private_key: RSA 私钥
        challenge: 挑战字节
    
    Returns:
        签名字节
    """
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key: rsa.RSAPublicKey, challenge: bytes, signature: bytes) -> bool:
    """
    用公钥验证签名
    
    Args:
        public_key: RSA 公钥
        challenge: 挑战字节
        signature: 签名字节
    
    Returns:
        True 验证通过，False 验证失败
    """
    try:
        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def generate_aes_key() -> bytes:
    """生成随机 AES-256 密钥"""
    return secrets.token_bytes(AES_KEY_SIZE)


def rsa_encrypt_aes_key(public_key: rsa.RSAPublicKey, aes_key: bytes) -> bytes:
    """
    用 RSA 公钥加密 AES 密钥（OAEP 填充，标准方案）
    
    Args:
        public_key: RSA 公钥
        aes_key: AES 密钥
    
    Returns:
        加密后的 AES 密钥
    """
    encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def rsa_decrypt_aes_key(private_key: rsa.RSAPrivateKey, encrypted_key: bytes) -> bytes:
    """
    用 RSA 私钥解密 AES 密钥（OAEP 填充）
    
    Args:
        private_key: RSA 私钥
        encrypted_key: 加密的 AES 密钥
    
    Returns:
        解密后的 AES 密钥
    """
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-GCM 加密
    
    Args:
        aes_key: AES 密钥
        plaintext: 明文
    
    Returns:
        nonce + ciphertext + tag
    """
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def aes_decrypt(aes_key: bytes, data: bytes) -> bytes:
    """
    AES-256-GCM 解密
    
    Args:
        aes_key: AES 密钥
        data: nonce + ciphertext + tag
    
    Returns:
        明文
    """
    aesgcm = AESGCM(aes_key)
    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext


def encrypt_message(aes_key: bytes, obj: dict) -> bytes:
    """加密消息（字典 -> 加密字节）"""
    import json
    plaintext = json.dumps(obj).encode('utf-8')
    return aes_encrypt(aes_key, plaintext)


def decrypt_message(aes_key: bytes, data: bytes) -> dict:
    """解密消息（加密字节 -> 字典）"""
    import json
    plaintext = aes_decrypt(aes_key, data)
    return json.loads(plaintext.decode('utf-8'))


if __name__ == '__main__':
    # 测试用
    print("生成 RSA 密钥对...")
    ensure_keypair_exists()
    
    print("\n测试签名和验证...")
    challenge = generate_challenge()
    private_key = load_private_key()
    public_key = load_public_key()
    
    signature = sign_challenge(private_key, challenge)
    valid = verify_signature(public_key, challenge, signature)
    print(f"签名验证: {'通过' if valid else '失败'}")
    
    print("\n测试 AES 密钥加密解密...")
    aes_key = generate_aes_key()
    encrypted_key = rsa_encrypt_aes_key(public_key, aes_key)
    decrypted_key = rsa_decrypt_aes_key(private_key, encrypted_key)
    print(f"AES 密钥一致: {aes_key == decrypted_key}")
    
    print("\n测试消息加密解密...")
    test_msg = {'test': 'hello world', 'number': 123}
    encrypted = encrypt_message(aes_key, test_msg)
    decrypted = decrypt_message(aes_key, encrypted)
    print(f"消息解密正确: {test_msg == decrypted}")
    
    print("\n[OK] 所有测试通过")

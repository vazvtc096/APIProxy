#!/usr/bin/env python3
"""
生成自签名 SSL 证书脚本
用于开发环境测试 HTTPS
生产环境请使用 Let's Encrypt 等正规证书
"""

import os
import ssl
from datetime import datetime, timedelta
from pathlib import Path

# 证书保存目录
CERT_DIR = os.path.join(os.path.dirname(__file__), 'certs')
CERT_FILE = os.path.join(CERT_DIR, 'server.crt')
KEY_FILE = os.path.join(CERT_DIR, 'server.key')

def generate_self_signed_cert(
    common_name: str = "localhost",
    country: str = "CN",
    state: str = "Beijing",
    city: str = "Beijing",
    organization: str = "API Proxy",
    valid_days: int = 365
) -> tuple[str, str]:
    """
    生成自签名 SSL 证书
    
    Args:
        common_name: 域名（如 localhost 或 your-domain.com）
        country: 国家代码（2位）
        state: 省份
        city: 城市
        organization: 组织名称
        valid_days: 有效期天数
    
    Returns:
        (证书路径, 私钥路径)
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        print("错误：需要安装 cryptography 库")
        print("请运行：pip install cryptography")
        return None, None
    
    # 创建证书目录
    os.makedirs(CERT_DIR, exist_ok=True)
    
    # 生成私钥
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # 设置证书主题
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # 生成证书
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress("127.0.0.1"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    
    # 写入证书
    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # 写入私钥
    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    
    print(f"[OK] 证书生成成功！")
    print(f"  证书文件: {CERT_FILE}")
    print(f"  私钥文件: {KEY_FILE}")
    print(f"  域名: {common_name}")
    print(f"  有效期: {valid_days} 天")
    print()
    print("使用方法：")
    print(f"  1. 设置环境变量：")
    print(f"     export SSL_ENABLED=true")
    print(f"     export SSL_CERT={CERT_FILE}")
    print(f"     export SSL_KEY={KEY_FILE}")
    print(f"  2. 启动应用：")
    print(f"     python -m user_project")
    print(f"  3. 访问：https://localhost:5443")
    print()
    print("注意：自签名证书在浏览器中会显示安全警告，这是正常的。")
    print("生产环境请使用 Let's Encrypt 等正规证书。")
    
    return CERT_FILE, KEY_FILE


if __name__ == "__main__":
    import sys
    
    # 从命令行参数获取域名
    domain = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    
    generate_self_signed_cert(common_name=domain)

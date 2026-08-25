#!/usr/bin/env python3
"""
RCON 远程控制台客户端
RSA 2048 + AES-256-GCM 混合加密
- RSA 用于密钥交换和认证
- AES-256-GCM 用于实际数据加密
- 每个连接生成新的 AES 会话密钥，15 分钟有效期
"""
import socket
import json
import sys
import os
import argparse
import time
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# AES-GCM 常量
NONCE_SIZE = 12  # 96 bits，GCM 推荐
AES_KEY_SIZE = 32  # AES-256

# 默认公钥文件路径
DEFAULT_PUBLIC_KEY_FILE = os.path.join(os.path.dirname(__file__), '.rcon_public.pem')


class RCONClient:
    def __init__(self, host: str, port: int, public_key_pem: bytes):
        """
        初始化 RCON 客户端
        
        Args:
            host: 服务器地址
            port: 服务器端口
            public_key_pem: 公钥 PEM 格式字节
        """
        self.host = host
        self.port = port
        self.public_key = serialization.load_pem_public_key(public_key_pem)
        self.sock = None
        self.aes_key = None
        self.connected = False
        self.key_expire_time = None
    
    def connect(self):
        """连接到 RCON 服务器并完成握手"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        
        try:
            self.sock.connect((self.host, self.port))
            
            # ========== 握手阶段 ==========
            
            # 1. 接收服务端的 hello 消息
            hello_data = self._recv_line()
            if not hello_data:
                raise Exception("连接失败：未收到服务端响应")
            
            try:
                hello_msg = json.loads(hello_data.decode('utf-8'))
            except json.JSONDecodeError:
                raise Exception("握手失败：服务端响应格式错误")
            
            if hello_msg.get('type') == 'error':
                raise Exception(f"握手失败：{hello_msg.get('message', '未知错误')}")
            
            # 2. 生成随机 AES 密钥
            self.aes_key = os.urandom(AES_KEY_SIZE)
            
            # 3. 用 RSA 公钥加密 AES 密钥
            encrypted_key = self.public_key.encrypt(
                self.aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 4. 发送加密的 AES 密钥（4 字节长度 + 加密数据）
            length = len(encrypted_key)
            self.sock.sendall(length.to_bytes(4, 'big') + encrypted_key)
            
            # 5. 接收握手成功响应（用 AES 密钥加密）
            handshake_resp = self._recv_encrypted()
            if not handshake_resp:
                raise Exception("握手失败：未收到服务端确认")
            
            if handshake_resp.get('type') != 'handshake_ok':
                raise Exception(f"握手失败：{handshake_resp.get('message', '未知错误')}")
            
            # 设置密钥过期时间
            expires_in = handshake_resp.get('expires_in', 15 * 60)
            self.key_expire_time = time.time() + expires_in
            
            self.connected = True
            
        except Exception as e:
            self.close()
            raise Exception(f"连接失败: {e}")
    
    def execute(self, command: str) -> dict:
        """执行命令"""
        if not self.connected:
            raise Exception("未连接")
        
        # 检查密钥是否即将过期
        if self.key_expire_time and time.time() > self.key_expire_time - 30:
            print("\n[!] 警告：AES 会话密钥即将过期，请重新连接")
        
        self._send_encrypted({'type': 'command', 'command': command})
        return self._recv_encrypted()
    
    def ping(self) -> bool:
        """发送心跳"""
        if not self.connected:
            return False
        try:
            self._send_encrypted({'type': 'ping'})
            resp = self._recv_encrypted()
            return resp and resp.get('type') == 'pong'
        except:
            return False
    
    def get_key_remaining(self) -> int:
        """获取密钥剩余时间（秒）"""
        if not self.connected:
            return 0
        try:
            self._send_encrypted({'type': 'key_remaining'})
            resp = self._recv_encrypted()
            if resp and resp.get('type') == 'key_remaining':
                return resp.get('remaining', 0)
            return 0
        except:
            return 0
    
    def _send_encrypted(self, obj: dict):
        """发送加密的 JSON 消息"""
        plaintext = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        encrypted = nonce + ciphertext
        
        # 先发 4 字节长度（大端序），再发加密数据
        length = len(encrypted)
        self.sock.sendall(length.to_bytes(4, 'big') + encrypted)
    
    def _recv_encrypted(self) -> dict | None:
        """接收加密的 JSON 消息"""
        # 先读 4 字节长度
        length_data = self._recv_exact(4)
        if length_data is None:
            return None
        length = int.from_bytes(length_data, 'big')
        
        # 再读加密数据
        encrypted = self._recv_exact(length)
        if encrypted is None:
            return None
        
        # 解密
        aesgcm = AESGCM(self.aes_key)
        nonce = encrypted[:NONCE_SIZE]
        ciphertext = encrypted[NONCE_SIZE:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        return json.loads(plaintext.decode('utf-8'))
    
    def _recv_line(self) -> bytes | None:
        """接收一行数据（以换行符结尾）"""
        data = b''
        while True:
            chunk = self.sock.recv(1)
            if not chunk:
                return None
            data += chunk
            if chunk == b'\n':
                break
        return data.strip()
    
    def _recv_exact(self, n: int) -> bytes | None:
        """精确读取 n 字节"""
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def close(self):
        """关闭连接"""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            self.aes_key = None


def format_result(result, indent=0):
    """格式化输出结果"""
    prefix = '  ' * indent
    
    if isinstance(result, str):
        # 多行字符串直接输出
        for line in result.split('\n'):
            print(f"{prefix}{line}")
    
    elif isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, (dict, list)):
                print(f"{prefix}{key}:")
                format_result(value, indent + 1)
            else:
                print(f"{prefix}{key}: {value}")
    
    elif isinstance(result, list):
        if len(result) == 0:
            print(f"{prefix}(空)")
        elif all(isinstance(item, dict) for item in result):
            # 列表中的字典，按表格形式输出
            if len(result) > 0:
                keys = list(result[0].keys())
                for i, item in enumerate(result, 1):
                    print(f"{prefix}[{i}] ", end='')
                    parts = []
                    for k in keys[:6]:  # 最多显示前6个字段
                        v = item.get(k, '')
                        if isinstance(v, str) and len(v) > 30:
                            v = v[:27] + '...'
                        parts.append(f"{k}={v}")
                    print(' | '.join(parts))
        else:
            for i, item in enumerate(result, 1):
                print(f"{prefix}[{i}] {item}")
    
    else:
        print(f"{prefix}{result}")


def interactive_mode(client: RCONClient):
    """交互式模式"""
    print("\nRCON 远程控制台 (输入 help 查看命令，exit 退出)")
    print("=" * 60)
    print(f"[OK] 已连接")
    print(f"  加密方式: RSA-2048 + AES-256-GCM")
    print(f"  密钥有效期: 15 分钟")
    print(f"  输入 'key_remaining' 查看剩余时间")
    print(f"  输入 'ping' 测试连接")
    print("=" * 60)
    print()
    
    while True:
        try:
            cmd = input("RCON> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见！")
            break
        
        if not cmd:
            continue
        
        if cmd.lower() in ('exit', 'quit', 'q'):
            print("再见！")
            break
        
        # 特殊命令：ping
        if cmd.lower() == 'ping':
            if client.ping():
                print("[OK] Pong! 连接正常")
            else:
                print("[X] 连接异常")
            continue
        
        # 特殊命令：key_remaining
        if cmd.lower() == 'key_remaining':
            remaining = client.get_key_remaining()
            if remaining > 0:
                minutes = remaining // 60
                seconds = remaining % 60
                print(f"密钥剩余时间: {minutes} 分 {seconds} 秒")
            else:
                print("密钥已过期，请重新连接")
            continue
        
        try:
            resp = client.execute(cmd)
            
            if resp.get('type') == 'response':
                output = resp.get('output', '')
                if output:
                    # 尝试解析为 JSON
                    try:
                        result_obj = json.loads(output)
                        format_result(result_obj)
                    except (json.JSONDecodeError, TypeError):
                        # 不是 JSON，直接输出
                        print(output)
            elif resp.get('type') == 'key_expired':
                print(f"\n[!] {resp.get('message', '密钥已过期')}")
                print("请重新连接")
                break
            else:
                # 其他类型的响应
                format_result(resp)
            
            # 如果是刷新密钥，提示用户
            if cmd.lower() == 'key refresh':
                print("\n[!] RSA 密钥对已刷新，当前连接将断开")
                print("请使用新的公钥重新连接")
                break
        
        except Exception as e:
            print(f"[X] 执行失败: {e}")
            break


def main():
    parser = argparse.ArgumentParser(description='RCON 远程控制台客户端 (RSA+AES 混合加密)')
    parser.add_argument('-H', '--host', default='127.0.0.1', help='服务器地址 (默认: 127.0.0.1)')
    parser.add_argument('-p', '--port', type=int, default=5001, help='端口 (默认: 5001)')
    parser.add_argument('-k', '--public-key', help='RSA 公钥文件路径')
    parser.add_argument('-c', '--command', help='执行单条命令后退出')
    parser.add_argument('--key-string', help='直接传入公钥 PEM 字符串')
    
    args = parser.parse_args()
    
    # 获取公钥
    public_key_pem = None
    
    if args.key_string:
        public_key_pem = args.key_string.encode('utf-8')
    elif args.public_key:
        try:
            with open(args.public_key, 'rb') as f:
                public_key_pem = f.read()
        except Exception as e:
            print(f"读取公钥文件失败: {e}")
            sys.exit(1)
    else:
        # 尝试默认路径
        if os.path.exists(DEFAULT_PUBLIC_KEY_FILE):
            try:
                with open(DEFAULT_PUBLIC_KEY_FILE, 'rb') as f:
                    public_key_pem = f.read()
            except Exception as e:
                print(f"读取默认公钥文件失败: {e}")
                sys.exit(1)
        else:
            print("错误: 请提供 RSA 公钥 (-k/--public-key 或 --key-string)")
            print(f"默认公钥文件不存在: {DEFAULT_PUBLIC_KEY_FILE}")
            sys.exit(1)
    
    # 验证公钥格式
    try:
        pub_key = serialization.load_pem_public_key(public_key_pem)
        key_size = pub_key.key_size
        print(f"公钥长度: {key_size} 位")
    except Exception as e:
        print(f"错误: 公钥格式无效: {e}")
        sys.exit(1)
    
    # 创建客户端
    client = RCONClient(args.host, args.port, public_key_pem)
    
    try:
        print(f"正在连接 {args.host}:{args.port} ...")
        client.connect()
        print("[OK] 握手成功 (RSA-2048 + AES-256-GCM 混合加密)")
        
        if args.command:
            # 单条命令模式
            resp = client.execute(args.command)
            if resp.get('type') == 'response':
                output = resp.get('output', '')
                if output:
                    print(output)
            else:
                print(json.dumps(resp, ensure_ascii=False, indent=2))
        else:
            # 交互式模式
            interactive_mode(client)
    
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as e:
        print(f"错误: {e}")
        sys.exit(1)
    finally:
        client.close()


if __name__ == '__main__':
    main()

"""
Debug Console 远程控制台服务端
最高权限级别（相当于 SYSTEM/root）
RSA 2048 + AES-256-GCM 混合加密
- RSA 用于密钥交换和认证
- AES-256-GCM 用于实际数据加密
- 每个连接生成新的 AES 会话密钥，15 分钟有效期
"""
import socket
import threading
import os
import time
import json
import logging
import datetime
from pathlib import Path

# 导入加密模块
from .debug_console_crypto import (
    load_private_key,
    ensure_keypair_exists,
    generate_rsa_keypair,
    save_keypair,
    rsa_decrypt_aes_key,
    aes_encrypt,
    aes_decrypt,
    encrypt_message,
    decrypt_message,
    generate_aes_key,
    AES_KEY_TTL,
    RSA_KEY_SIZE,
    PRIVATE_KEY_FILE,
    PUBLIC_KEY_FILE,
)

# 配置
DEBUG_CONSOLE_PORT = 5001
MAX_CONNECTIONS = 1  # 单连接限制

# 全局状态
_debug_console_server = None
_current_conn = None  # 当前连接
_current_aes_key = None  # 当前 AES 会话密钥
_aes_key_expire_time = None  # AES 密钥过期时间
_conn_lock = threading.Lock()
_running = False

# 命令处理器（复用 debug_console.py 的）
_handler = None


def _get_handler():
    """获取命令处理器"""
    global _handler
    if _handler is None:
        from .debug_console import DebugConsoleCommandHandler
        _handler = DebugConsoleCommandHandler()
    return _handler


def refresh_debug_console_keypair() -> str:
    """
    重新生成 RSA 密钥对
    
    Returns:
        新的公钥指纹或提示信息
    """
    private_pem, public_pem = generate_rsa_keypair()
    save_keypair(private_pem, public_pem)
    
    # 断开当前连接（因为密钥变了）
    global _current_conn, _current_aes_key, _aes_key_expire_time
    with _conn_lock:
        if _current_conn:
            try:
                _current_conn.close()
            except:
                pass
            _current_conn = None
            _current_aes_key = None
            _aes_key_expire_time = None
    
    logging.info("Debug Console RSA keypair refreshed")
    return f"RSA {RSA_KEY_SIZE} 位密钥对已刷新，旧连接已断开\n新公钥: {PUBLIC_KEY_FILE}"


def _send_encrypted(conn, aes_key: bytes, obj: dict):
    """发送加密消息"""
    encrypted = encrypt_message(aes_key, obj)
    # 4 字节长度（大端） + 加密数据
    length = len(encrypted)
    conn.sendall(length.to_bytes(4, 'big') + encrypted)


def _recv_encrypted(conn, aes_key: bytes) -> dict | None:
    """接收加密消息"""
    try:
        # 先读 4 字节长度
        length_data = _recv_exact(conn, 4)
        if length_data is None:
            return None
        length = int.from_bytes(length_data, 'big')
        
        # 读取加密数据
        encrypted = _recv_exact(conn, length)
        if encrypted is None:
            return None
        
        # 解密
        return decrypt_message(aes_key, encrypted)
    except Exception:
        return None


def _recv_exact(conn, length: int) -> bytes | None:
    """精确读取指定字节数"""
    data = b''
    while len(data) < length:
        try:
            chunk = conn.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        except:
            return None
    return data


def _handle_client(conn, addr):
    """处理客户端连接"""
    global _current_conn, _current_aes_key, _aes_key_expire_time
    
    logging.info(f"Debug Console client connected: {addr}")
    
    try:
        # ========== 握手阶段 ==========
        
        # 1. 加载私钥
        private_key = load_private_key()
        
        # 2. 发送握手欢迎信息（明文，告诉客户端服务端就绪）
        hello_msg = {
            'type': 'hello',
            'version': '2.0',
            'encryption': 'RSA-2048 + AES-256-GCM',
            'key_ttl': AES_KEY_TTL,
        }
        conn.sendall(json.dumps(hello_msg).encode('utf-8') + b'\n')
        
        # 3. 接收客户端发送的加密 AES 密钥
        # 先读 4 字节长度
        length_data = _recv_exact(conn, 4)
        if length_data is None:
            logging.warning("Client disconnected during handshake")
            return
        
        length = int.from_bytes(length_data, 'big')
        if length > 1024:  # 合理限制
            logging.warning(f"Invalid key length: {length}")
            return
        
        encrypted_key = _recv_exact(conn, length)
        if encrypted_key is None:
            logging.warning("Client disconnected during key exchange")
            return
        
        # 4. 解密得到 AES 密钥
        try:
            aes_key = rsa_decrypt_aes_key(private_key, encrypted_key)
        except Exception as e:
            logging.warning(f"Failed to decrypt AES key: {e}")
            error_msg = {'type': 'error', 'message': 'Key exchange failed'}
            conn.sendall(json.dumps(error_msg).encode('utf-8') + b'\n')
            return
        
        # 5. 发送握手成功响应（用新的 AES 密钥加密）
        handshake_ok = {
            'type': 'handshake_ok',
            'message': 'Handshake successful',
            'expires_in': AES_KEY_TTL,
        }
        _send_encrypted(conn, aes_key, handshake_ok)
        
        # 6. 更新全局状态
        with _conn_lock:
            if _current_conn and _current_conn != conn:
                # 踢掉之前的连接
                try:
                    _current_conn.close()
                except:
                    pass
            _current_conn = conn
            _current_aes_key = aes_key
            _aes_key_expire_time = time.time() + AES_KEY_TTL
        
        logging.info(f"Debug Console handshake successful: {addr}")
        
        # ========== 命令处理循环 ==========
        handler = _get_handler()
        
        while _running:
            # 检查 AES 密钥是否过期
            if time.time() > _aes_key_expire_time:
                expire_msg = {
                    'type': 'key_expired',
                    'message': 'AES session key expired, please reconnect',
                }
                _send_encrypted(conn, aes_key, expire_msg)
                logging.info(f"AES key expired, disconnecting: {addr}")
                break
            
            # 接收加密消息
            msg = _recv_encrypted(conn, aes_key)
            if msg is None:
                break
            
            msg_type = msg.get('type', '')
            
            if msg_type == 'command':
                # 执行命令
                command = msg.get('command', '')
                if not command:
                    continue
                
                # 特殊处理 key refresh 命令
                if command.strip() == 'key refresh':
                    result = refresh_debug_console_keypair()
                    response = {
                        'type': 'response',
                        'command': command,
                        'output': result,
                    }
                    _send_encrypted(conn, aes_key, response)
                    # key refresh 后断开连接
                    break
                
                # 执行普通命令
                import asyncio
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(handler.handle(command))
                finally:
                    loop.close()
                
                response = {
                    'type': 'response',
                    'command': command,
                    'output': result,
                }
                _send_encrypted(conn, aes_key, response)
            
            elif msg_type == 'ping':
                # 心跳
                pong = {'type': 'pong', 'timestamp': time.time()}
                _send_encrypted(conn, aes_key, pong)
            
            elif msg_type == 'key_remaining':
                # 查询密钥剩余时间
                remaining = max(0, _aes_key_expire_time - time.time())
                response = {
                    'type': 'key_remaining',
                    'remaining': int(remaining),
                }
                _send_encrypted(conn, aes_key, response)
            
            elif msg_type == 'quit' or msg_type == 'exit':
                break
    
    except Exception as e:
        logging.error(f"Debug Console client error: {e}")
    finally:
        # 清理连接状态
        with _conn_lock:
            if _current_conn == conn:
                _current_conn = None
                _current_aes_key = None
                _aes_key_expire_time = None
        try:
            conn.close()
        except:
            pass
        logging.info(f"Debug Console client disconnected: {addr}")


def start_debug_console_server():
    """启动 Debug Console 服务器（阻塞式）"""
    global _running, _debug_console_server
    
    # 确保 RSA 密钥对存在
    ensure_keypair_exists()
    
    _running = True
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', DEBUG_CONSOLE_PORT))
    server.listen(MAX_CONNECTIONS)
    
    _debug_console_server = server
    
    logging.info(f"Debug Console server started on port {DEBUG_CONSOLE_PORT}")
    logging.info(f"Encryption: RSA-{RSA_KEY_SIZE} + AES-256-GCM")
    logging.info(f"Private key: {PRIVATE_KEY_FILE}")
    logging.info(f"Public key: {PUBLIC_KEY_FILE}")
    print(f"Debug Console 服务器已启动，端口: {DEBUG_CONSOLE_PORT}")
    print(f"加密方式: RSA-{RSA_KEY_SIZE} + AES-256-GCM")
    print(f"私钥: {PRIVATE_KEY_FILE}")
    print(f"公钥: {PUBLIC_KEY_FILE}")
    
    try:
        while _running:
            try:
                conn, addr = server.accept()
                # 每个连接在单独线程处理
                thread = threading.Thread(
                    target=_handle_client,
                    args=(conn, addr),
                    daemon=True,
                    name=f'Debug Console-Client-{addr[0]}'
                )
                thread.start()
            except Exception as e:
                if _running:
                    logging.error(f"Accept error: {e}")
    finally:
        _running = False
        server.close()


def start_debug_console_server_thread():
    """在独立线程中启动 Debug Console 服务器"""
    thread = threading.Thread(
        target=start_debug_console_server,
        daemon=True,
        name='Debug Console-Server'
    )
    thread.start()
    return thread


def stop_debug_console_server():
    """停止 Debug Console 服务器"""
    global _running, _debug_console_server
    _running = False
    if _debug_console_server:
        try:
            _debug_console_server.close()
        except:
            pass
        _debug_console_server = None


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    start_debug_console_server()

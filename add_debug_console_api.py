import sys

with open('__main__.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 找到插入位置
marker = """    return jsonify({
        'message': 'User created successfully',
        'username': username,
        'uid': uid,
        'email': email,
        'is_admin': is_admin,
        'balence': initial_balence
    }), 201


@app.route('/api/admin/user/<uid>/email', methods=['PUT'])
async def admin_set_email(uid):"""

if marker not in content:
    print("ERROR: Could not find insertion point")
    sys.exit(1)

# Debug Console API 代码
debug_console_api_code = '''    return jsonify({
        'message': 'User created successfully',
        'username': username,
        'uid': uid,
        'email': email,
        'is_admin': is_admin,
        'balence': initial_balence
    }), 201


# ---------- Debug Console 密钥管理（管理员） ----------

@app.route('/api/admin/debug-console-keys', methods=['GET'])
async def admin_list_debug_console_keys():
    """管理员列出所有 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    keys = await _list_debug_console_keys()
    return jsonify({'keys': keys}), 200


@app.route('/api/admin/debug-console-keys', methods=['POST'])
async def admin_create_debug_console_key():
    """管理员生成新的 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    data = await request.get_json()
    key_name = data.get('name', 'default') if data else 'default'
    
    new_key = await _generate_debug_console_key(key_name)
    
    admin_name = session['user']
    logging.info(f"Admin created Debug Console key: {key_name}, admin: {admin_name}")
    
    return jsonify({
        'message': 'Debug Console key created successfully',
        'key': new_key,  # 只返回一次明文
        'name': key_name
    }), 201


@app.route('/api/admin/debug-console-keys/<int:key_id>', methods=['DELETE'])
async def admin_revoke_debug_console_key(key_id):
    """管理员撤销 Debug Console 密钥"""
    err = await _require_admin()
    if err:
        return err
    
    success = await _revoke_debug_console_key(key_id)
    if not success:
        return jsonify({'error': 'Debug Console key not found'}), 404
    
    admin_name = session['user']
    logging.info(f"Admin revoked Debug Console key: {key_id}, admin: {admin_name}")
    
    return jsonify({'message': 'Debug Console key revoked successfully'}), 200


# ---------- Debug Console 执行接口 ----------

@app.route('/api/debug-console', methods=['POST'])
async def debug_console_execute():
    """Debug Console 远程命令执行"""
    # 从 Header 或 Body 获取密钥
    debug_console_key = request.headers.get('X-Debug-Console-Key', '')
    if not debug_console_key:
        data = await request.get_json(silent=True)
        if data:
            debug_console_key = data.get('key', '')
    
    if not debug_console_key:
        return jsonify({'error': 'Debug Console key required'}), 401
    
    # 获取客户端 IP（兼容反向代理 / Cloudflare）
    client_ip = _get_client_ip()
    
    # 验证密钥
    valid = await _validate_debug_console_key(debug_console_key, client_ip)
    if not valid:
        return jsonify({'error': 'Invalid Debug Console key'}), 401
    
    # 获取命令
    data = await request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Command required'}), 400
    
    command = data.get('command', '').strip()
    args = data.get('args', [])
    
    if not command:
        return jsonify({'error': 'Command required'}), 400
    
    # 执行命令
    result = await _execute_debug_console_command(command, args)
    
    # 记录日志
    logging.info(f"Debug Console command executed: {command} {args}, from {client_ip}")
    
    return jsonify(result), 200 if result['success'] else 400


@app.route('/api/admin/user/<uid>/email', methods=['PUT'])
async def admin_set_email(uid):'''

content = content.replace(marker, debug_console_api_code)

with open('__main__.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("SUCCESS: Added Debug Console API routes")

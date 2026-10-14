package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.DebugConsoleConfig;
import com.apiproxy.entity.DebugConsoleKeys;
import com.apiproxy.service.DebugConsoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Debug Console Controller。
 *
 * 对应 Python routes/debug_console_routes.py + debug_console_server.py：
 * - GET  /api/debug-console/configs          列出 Debug Console 配置
 * - POST /api/debug-console/configs          创建 Debug Console 配置
 * - DELETE /api/debug-console/configs/{id}   删除 Debug Console 配置
 * - GET  /api/debug-console/keys             列出 Debug Console 密钥
 * - POST /api/debug-console/keys             生成 Debug Console 密钥
 * - POST /api/debug-console/execute          执行 Debug Console 命令
 * - POST /api/debug-console/session          创建 Debug Console 会话
 * - POST /api/debug-console/session/{id}/cmd 会话内执行命令
 * - DELETE /api/debug-console/session/{id}    关闭会话
 */
@RestController
@RequestMapping("/api/debug-console")
public class DebugConsoleController {

    private final DebugConsoleService debugConsoleService;

    public DebugConsoleController(DebugConsoleService debugConsoleService) {
        this.debugConsoleService = debugConsoleService;
    }

    // ---------- 配置管理 ----------

    @GetMapping("/configs")
    public ResponseEntity<ApiResponse> listConfigs() {
        return ResponseEntity.ok(ApiResponse.ok(debugConsoleService.listConfigs()));
    }

    @PostMapping("/configs")
    public ResponseEntity<ApiResponse> createConfig(@RequestBody Map<String, Object> body) {
        String name = str(body.get("name"));
        String host = str(body.get("host"));
        int port = Integer.parseInt(str(body.get("port")));
        String password = str(body.get("password"));
        DebugConsoleConfig cfg = debugConsoleService.createConfig(name, host, port, password);
        return ResponseEntity.ok(ApiResponse.ok("Debug Console config created", cfg));
    }

    @DeleteMapping("/configs/{id}")
    public ResponseEntity<ApiResponse> deleteConfig(@PathVariable Long id) {
        debugConsoleService.deleteConfig(id);
        return ResponseEntity.ok(ApiResponse.ok("Debug Console config deleted"));
    }

    // ---------- 密钥管理 ----------

    @GetMapping("/keys")
    public ResponseEntity<ApiResponse> listKeys() {
        return ResponseEntity.ok(ApiResponse.ok(debugConsoleService.listKeys()));
    }

    @PostMapping("/keys")
    public ResponseEntity<ApiResponse> generateKey(@RequestBody Map<String, Object> body) {
        String name = str(body.get("name"));
        String permission = str(body.get("permission"));
        DebugConsoleKeys key = debugConsoleService.generateKey(name, permission);
        return ResponseEntity.ok(ApiResponse.ok("Debug Console key generated", key));
    }

    // ---------- 命令执行 ----------

    @PostMapping("/execute")
    public ResponseEntity<ApiResponse> execute(@RequestBody Map<String, Object> body) {
        Long configId = Long.parseLong(str(body.get("config_id")));
        String command = str(body.get("command"));
        try {
            String result = debugConsoleService.executeByConfigId(configId, command);
            return ResponseEntity.ok(ApiResponse.ok("Command executed", Map.of("output", result)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    // ---------- 会话管理 ----------

    @PostMapping("/session")
    public ResponseEntity<ApiResponse> createSession(@RequestBody Map<String, Object> body) {
        String host = str(body.get("host"));
        int port = Integer.parseInt(str(body.get("port")));
        String password = str(body.get("password"));
        try {
            String sessionId = debugConsoleService.createSession(host, port, password);
            return ResponseEntity.ok(ApiResponse.ok("Session created", Map.of("session_id", sessionId)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/session/{id}/cmd")
    public ResponseEntity<ApiResponse> sessionCommand(
            @PathVariable String id,
            @RequestBody Map<String, Object> body) {
        String command = str(body.get("command"));
        try {
            String result = debugConsoleService.executeInSession(id, command);
            return ResponseEntity.ok(ApiResponse.ok(Map.of("output", result)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @DeleteMapping("/session/{id}")
    public ResponseEntity<ApiResponse> closeSession(@PathVariable String id) {
        debugConsoleService.closeSession(id);
        return ResponseEntity.ok(ApiResponse.ok("Session closed"));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

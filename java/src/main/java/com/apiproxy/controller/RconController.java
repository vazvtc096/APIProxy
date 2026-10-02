package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.RconConfig;
import com.apiproxy.entity.RconKeys;
import com.apiproxy.service.RconService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * RCON Controller。
 *
 * 对应 Python routes/rcon_routes.py + rcon_server.py：
 * - GET  /api/rcon/configs          列出 RCON 配置
 * - POST /api/rcon/configs          创建 RCON 配置
 * - DELETE /api/rcon/configs/{id}   删除 RCON 配置
 * - GET  /api/rcon/keys             列出 RCON 密钥
 * - POST /api/rcon/keys             生成 RCON 密钥
 * - POST /api/rcon/execute          执行 RCON 命令
 * - POST /api/rcon/session          创建 RCON 会话
 * - POST /api/rcon/session/{id}/cmd 会话内执行命令
 * - DELETE /api/rcon/session/{id}    关闭会话
 */
@RestController
@RequestMapping("/api/rcon")
public class RconController {

    private final RconService rconService;

    public RconController(RconService rconService) {
        this.rconService = rconService;
    }

    // ---------- 配置管理 ----------

    @GetMapping("/configs")
    public ResponseEntity<ApiResponse> listConfigs() {
        return ResponseEntity.ok(ApiResponse.ok(rconService.listConfigs()));
    }

    @PostMapping("/configs")
    public ResponseEntity<ApiResponse> createConfig(@RequestBody Map<String, Object> body) {
        String name = str(body.get("name"));
        String host = str(body.get("host"));
        int port = Integer.parseInt(str(body.get("port")));
        String password = str(body.get("password"));
        RconConfig cfg = rconService.createConfig(name, host, port, password);
        return ResponseEntity.ok(ApiResponse.ok("RCON config created", cfg));
    }

    @DeleteMapping("/configs/{id}")
    public ResponseEntity<ApiResponse> deleteConfig(@PathVariable Long id) {
        rconService.deleteConfig(id);
        return ResponseEntity.ok(ApiResponse.ok("RCON config deleted"));
    }

    // ---------- 密钥管理 ----------

    @GetMapping("/keys")
    public ResponseEntity<ApiResponse> listKeys() {
        return ResponseEntity.ok(ApiResponse.ok(rconService.listKeys()));
    }

    @PostMapping("/keys")
    public ResponseEntity<ApiResponse> generateKey(@RequestBody Map<String, Object> body) {
        String name = str(body.get("name"));
        String permission = str(body.get("permission"));
        RconKeys key = rconService.generateKey(name, permission);
        return ResponseEntity.ok(ApiResponse.ok("RCON key generated", key));
    }

    // ---------- 命令执行 ----------

    @PostMapping("/execute")
    public ResponseEntity<ApiResponse> execute(@RequestBody Map<String, Object> body) {
        Long configId = Long.parseLong(str(body.get("config_id")));
        String command = str(body.get("command"));
        try {
            String result = rconService.executeByConfigId(configId, command);
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
            String sessionId = rconService.createSession(host, port, password);
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
            String result = rconService.executeInSession(id, command);
            return ResponseEntity.ok(ApiResponse.ok(Map.of("output", result)));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @DeleteMapping("/session/{id}")
    public ResponseEntity<ApiResponse> closeSession(@PathVariable String id) {
        rconService.closeSession(id);
        return ResponseEntity.ok(ApiResponse.ok("Session closed"));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

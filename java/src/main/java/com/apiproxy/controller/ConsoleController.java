package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.ConfigKv;
import com.apiproxy.service.ConsoleService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 控制台 Controller。
 *
 * 对应 Python routes/console_routes.py + core_console.py：
 * - GET  /api/console/configs        列出所有 KV 配置
 * - GET  /api/console/config/{key}   获取配置
 * - POST /api/console/config          设置配置
 * - DELETE /api/console/config/{key} 删除配置
 * - GET  /api/console/system-info     系统信息
 * - POST /api/console/execute         执行控制台命令
 */
@RestController
@RequestMapping("/api/console")
public class ConsoleController {

    private final ConsoleService consoleService;

    public ConsoleController(ConsoleService consoleService) {
        this.consoleService = consoleService;
    }

    @GetMapping("/configs")
    public ResponseEntity<ApiResponse> listConfigs() {
        List<ConfigKv> configs = consoleService.listAllConfigs();
        return ResponseEntity.ok(ApiResponse.ok(configs));
    }

    @GetMapping("/config/{key}")
    public ResponseEntity<ApiResponse> getConfig(@PathVariable String key) {
        String value = consoleService.getConfig(key);
        if (value == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(ApiResponse.ok(Map.of("key", key, "value", value)));
    }

    @PostMapping("/config")
    public ResponseEntity<ApiResponse> setConfig(@RequestBody Map<String, Object> body) {
        String key = str(body.get("key"));
        String value = str(body.get("value"));
        consoleService.setConfig(key, value);
        return ResponseEntity.ok(ApiResponse.ok("Config set"));
    }

    @DeleteMapping("/config/{key}")
    public ResponseEntity<ApiResponse> deleteConfig(@PathVariable String key) {
        consoleService.deleteConfig(key);
        return ResponseEntity.ok(ApiResponse.ok("Config deleted"));
    }

    @GetMapping("/system-info")
    public ResponseEntity<ApiResponse> systemInfo() {
        return ResponseEntity.ok(ApiResponse.ok(consoleService.getSystemInfo()));
    }

    @PostMapping("/execute")
    public ResponseEntity<ApiResponse> execute(@RequestBody Map<String, Object> body) {
        String command = str(body.get("command"));
        @SuppressWarnings("unchecked")
        Map<String, Object> args = (Map<String, Object>) body.getOrDefault("args", Map.of());
        try {
            Map<String, Object> result = consoleService.executeCommand(command, args);
            return ResponseEntity.ok(ApiResponse.ok(result));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

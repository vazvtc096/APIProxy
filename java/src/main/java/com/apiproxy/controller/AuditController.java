package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.AuditLog;
import com.apiproxy.entity.LoginLog;
import com.apiproxy.entity.WebAccessLog;
import com.apiproxy.service.AuditService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Map;

/**
 * 审计日志 Controller。
 *
 * 对应 Python routes/audit_routes.py：
 * - GET /api/audit/logs          审计日志查询
 * - GET /api/audit/login-logs    登录日志查询
 * - GET /api/audit/access-logs   Web 访问日志查询
 * - GET /api/audit/stats         审计统计
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping("/logs")
    public ResponseEntity<ApiResponse> auditLogs(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String resource,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditLog> logs = auditService.queryAuditLogs(username, action, resource, page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", logs.getContent(),
                "total", logs.getTotalElements()
        )));
    }

    @GetMapping("/login-logs")
    public ResponseEntity<ApiResponse> loginLogs(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) Boolean success,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<LoginLog> logs = auditService.queryLoginLogs(username, success, page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", logs.getContent(),
                "total", logs.getTotalElements()
        )));
    }

    @GetMapping("/access-logs")
    public ResponseEntity<ApiResponse> accessLogs(
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) String path,
            @RequestParam(required = false) Integer status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "100") int size) {
        Page<WebAccessLog> logs = auditService.queryWebAccessLogs(ip, path, status, page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", logs.getContent(),
                "total", logs.getTotalElements()
        )));
    }

    @GetMapping("/stats")
    public ResponseEntity<ApiResponse> stats() {
        LocalDateTime since = LocalDateTime.now().minus(24, ChronoUnit.HOURS);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "requests_24h", auditService.countRequestsSince(since),
                "unique_ips_24h", auditService.countUniqueIpsSince(since)
        )));
    }
}

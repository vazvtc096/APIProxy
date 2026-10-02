package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.repository.UserRepository;
import com.apiproxy.repository.UsageLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.sql.Connection;
import java.time.Instant;
import java.util.Map;

/**
 * 健康检查 Controller。
 *
 * 对应 Python routes/health.py：
 * - GET /health         基础存活探针（liveness）
 * - GET /ready          就绪探针（readiness，检查 DB）
 * - GET /api/health     详细健康状态（版本、运行时长、用户数、请求数）
 */
@RestController
public class HealthController {

    private final DataSource dataSource;
    private final UserRepository userRepository;
    private final UsageLogRepository usageLogRepository;

    @Value("${apiproxy.version:1.0.0}")
    private String version;

    private final long startTime = Instant.now().getEpochSecond();

    public HealthController(DataSource dataSource,
                            UserRepository userRepository,
                            UsageLogRepository usageLogRepository) {
        this.dataSource = dataSource;
        this.userRepository = userRepository;
        this.usageLogRepository = usageLogRepository;
    }

    /** 基础存活探针 */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "ok",
                "timestamp", Instant.now().toString()
        ));
    }

    /** 就绪探针：检查数据库连接 */
    @GetMapping("/ready")
    public ResponseEntity<Map<String, Object>> ready() {
        boolean dbOk = false;
        try (Connection conn = dataSource.getConnection()) {
            dbOk = conn.isValid(2);
        } catch (Exception ignored) {}
        if (!dbOk) {
            return ResponseEntity.status(503).body(Map.of(
                    "status", "not_ready",
                    "database", "unavailable"
            ));
        }
        return ResponseEntity.ok(Map.of(
                "status", "ready",
                "database", "ok"
        ));
    }

    /** 详细健康状态 */
    @GetMapping("/api/health")
    public ResponseEntity<ApiResponse> detailedHealth() {
        long uptime = Instant.now().getEpochSecond() - startTime;
        long userCount = userRepository.count();
        long requestCount = usageLogRepository.count();
        return ResponseEntity.ok(ApiResponse.ok("healthy", Map.of(
                "version", version,
                "uptime_seconds", uptime,
                "users", userCount,
                "total_requests", requestCount,
                "timestamp", Instant.now().toString()
        )));
    }
}

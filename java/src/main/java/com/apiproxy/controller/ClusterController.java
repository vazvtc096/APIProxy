package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.service.ClusterService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 集群管理 Controller。
 *
 * 对应 Python routes/cluster_routes.py + cluster.py：
 * - GET  /api/cluster/status     集群状态
 * - GET  /api/cluster/nodes      活跃节点列表
 * - POST /api/cluster/register   节点注册
 * - POST /api/cluster/heartbeat  心跳上报
 * - POST /api/cluster/sync       同步集群配置
 */
@RestController
@RequestMapping("/api/cluster")
public class ClusterController {

    private final ClusterService clusterService;

    public ClusterController(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    @GetMapping("/status")
    public ResponseEntity<ApiResponse> status() {
        return ResponseEntity.ok(ApiResponse.ok(clusterService.getClusterStatus()));
    }

    @GetMapping("/nodes")
    public ResponseEntity<ApiResponse> nodes() {
        return ResponseEntity.ok(ApiResponse.ok(clusterService.getActiveNodes()));
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@RequestBody Map<String, Object> body) {
        String host = str(body.get("host"));
        int port = Integer.parseInt(str(body.get("port")));
        clusterService.registerNode(host, port);
        return ResponseEntity.ok(ApiResponse.ok("Node registered"));
    }

    @PostMapping("/heartbeat")
    public ResponseEntity<ApiResponse> heartbeat() {
        clusterService.heartbeat();
        return ResponseEntity.ok(ApiResponse.ok("Heartbeat received"));
    }

    @PostMapping("/sync")
    public ResponseEntity<ApiResponse> sync() {
        clusterService.syncClusterConfig();
        return ResponseEntity.ok(ApiResponse.ok("Cluster config synced"));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

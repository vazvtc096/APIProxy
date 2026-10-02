package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.*;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.AdminService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 管理后台 API Controller。
 *
 * 对应 Python routes/admin.py 的所有管理 API 端点。
 * 所有端点需 ADMIN 角色（已在 SecurityConfig 配置 /api/admin/** 需 ROLE_ADMIN）。
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    // ---------- 仪表盘 ----------

    @GetMapping("/dashboard/stats")
    public ResponseEntity<ApiResponse> dashboardStats() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.getDashboardStats()));
    }

    // ---------- 用户管理 ----------

    @GetMapping("/users")
    public ResponseEntity<ApiResponse> listUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String search) {
        Page<User> users = adminService.listUsers(page, size, search);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", users.getContent(),
                "total", users.getTotalElements(),
                "page", users.getNumber(),
                "size", users.getSize()
        )));
    }

    @PostMapping("/users/{username}/ban")
    public ResponseEntity<ApiResponse> banUser(
            @PathVariable String username,
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String reason = str(body.get("reason"));
        adminService.banUser(username, reason, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("User banned"));
    }

    @PostMapping("/users/{username}/unban")
    public ResponseEntity<ApiResponse> unbanUser(
            @PathVariable String username,
            @AuthenticationPrincipal CustomUserDetails principal) {
        adminService.unbanUser(username, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("User unbanned"));
    }

    @PostMapping("/users/{username}/role")
    public ResponseEntity<ApiResponse> setRole(
            @PathVariable String username,
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String role = str(body.get("role"));
        adminService.setUserRole(username, role, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Role updated"));
    }

    // ---------- 公告管理 ----------

    @GetMapping("/announcements")
    public ResponseEntity<ApiResponse> listAnnouncements(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<Announcement> list = adminService.listAnnouncements(page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    @PostMapping("/announcements")
    public ResponseEntity<ApiResponse> createAnnouncement(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String title = str(body.get("title"));
        String content = str(body.get("content"));
        boolean pinned = Boolean.TRUE.equals(body.get("pinned"));
        Announcement ann = adminService.createAnnouncement(title, content, principal.getUsername(), pinned);
        return ResponseEntity.ok(ApiResponse.ok("Announcement created", ann));
    }

    @DeleteMapping("/announcements/{id}")
    public ResponseEntity<ApiResponse> deleteAnnouncement(@PathVariable Integer id) {
        adminService.deleteAnnouncement(id);
        return ResponseEntity.ok(ApiResponse.ok("Announcement deleted"));
    }

    // ---------- IP 黑名单 ----------

    @GetMapping("/ip-blacklist")
    public ResponseEntity<ApiResponse> listBlacklistedIps() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.listBlacklistedIps()));
    }

    @PostMapping("/ip-blacklist")
    public ResponseEntity<ApiResponse> addBlacklistedIp(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String ip = str(body.get("ip"));
        String reason = str(body.get("reason"));
        adminService.addBlacklistedIp(ip, reason, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("IP blacklisted"));
    }

    @DeleteMapping("/ip-blacklist/{ip}")
    public ResponseEntity<ApiResponse> removeBlacklistedIp(@PathVariable String ip) {
        adminService.removeBlacklistedIp(ip);
        return ResponseEntity.ok(ApiResponse.ok("IP removed from blacklist"));
    }

    // ---------- 设备封禁 ----------

    @GetMapping("/device-bans")
    public ResponseEntity<ApiResponse> listDeviceBans(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<DeviceBan> list = adminService.listDeviceBans(page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    // ---------- Hooks ----------

    @GetMapping("/hooks")
    public ResponseEntity<ApiResponse> listHooks(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<Hooks> list = adminService.listHooks(page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    // ---------- 帖子管理 ----------

    @GetMapping("/posts")
    public ResponseEntity<ApiResponse> listPosts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<Post> list = adminService.listPosts(page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    @DeleteMapping("/posts/{id}")
    public ResponseEntity<ApiResponse> deletePost(
            @PathVariable Integer id,
            @AuthenticationPrincipal CustomUserDetails principal) {
        adminService.deletePost(id, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Post deleted"));
    }

    // ---------- 定时任务 ----------

    @GetMapping("/tasks")
    public ResponseEntity<ApiResponse> listTasks() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.listScheduledTasks()));
    }

    @PostMapping("/tasks/{id}/toggle")
    public ResponseEntity<ApiResponse> toggleTask(
            @PathVariable Long id,
            @RequestBody Map<String, Object> body) {
        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        adminService.toggleTask(id, enabled);
        return ResponseEntity.ok(ApiResponse.ok("Task updated"));
    }

    // ---------- 审计日志 ----------

    @GetMapping("/audit-logs")
    public ResponseEntity<ApiResponse> listAuditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String username) {
        Page<AuditLog> list = adminService.listAuditLogs(page, size, action, username);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    // ---------- 系统配置 ----------

    @GetMapping("/configs")
    public ResponseEntity<ApiResponse> listConfigs() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.listSystemConfigs()));
    }

    @PostMapping("/configs")
    public ResponseEntity<ApiResponse> updateConfig(@RequestBody Map<String, Object> body) {
        String key = str(body.get("key"));
        String value = str(body.get("value"));
        adminService.updateSystemConfig(key, value);
        return ResponseEntity.ok(ApiResponse.ok("Config updated"));
    }

    // ---------- 上游节点 ----------

    @GetMapping("/upstreams")
    public ResponseEntity<ApiResponse> listUpstreams() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.listUpstreams()));
    }

    // ---------- 定价 ----------

    @GetMapping("/prices")
    public ResponseEntity<ApiResponse> listPrices() {
        return ResponseEntity.ok(ApiResponse.ok(adminService.listModelPrices()));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

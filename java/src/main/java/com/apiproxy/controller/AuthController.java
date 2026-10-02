package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.AuthService;
import com.apiproxy.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 认证 Controller：注册 / 密码重置 / 修改密码 / 登出回调。
 *
 * 对应 Python routes/auth.py 的端点（除 /login 由 Spring Security 表单登录接管）：
 * - POST /register
 * - POST /api/password-reset/request
 * - POST /api/password-reset/confirm
 * - POST /api/user/change-password
 *
 * /logout 已在 SecurityConfig.logout() 配置，无需在此实现。
 */
@RestController
public class AuthController {

    private final AuthService authService;
    private final RateLimitService rateLimit;

    public AuthController(AuthService authService, RateLimitService rateLimit) {
        this.authService = authService;
        this.rateLimit = rateLimit;
    }

    /**
     * 注册新用户。
     * 对齐 Python /register：限流 → 输入校验 → 邮箱验证码/滑块验证 → 建用户 → admin 好友。
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@RequestBody Map<String, Object> body,
                                                 HttpServletRequest request) {
        // 限流（按 IP 维度，对齐 Python _check_rate_limit('register')）
        String ip = getClientIp(request);
        if (!rateLimit.allow("register", ip)) {
            long retry = rateLimit.retryAfter("register", ip);
            HttpHeaders headers = new HttpHeaders();
            headers.add("Retry-After", String.valueOf(retry));
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .headers(headers)
                    .body(ApiResponse.fail("Too many requests, please try again later"));
        }

        String username = str(body.get("username"));
        String password = str(body.get("password"));
        String email = str(body.get("email"));
        String code = str(body.get("code"));

        try {
            String uid = authService.register(username, password, email, code);
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.ok("User registered successfully", Map.of("uid", uid)));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    /**
     * 请求密码重置：发送验证码到绑定邮箱。
     * 无论用户是否存在都返回相同提示（防用户名枚举）。
     */
    @PostMapping("/api/password-reset/request")
    public ResponseEntity<ApiResponse> passwordResetRequest(@RequestBody Map<String, Object> body,
                                                             HttpServletRequest request) {
        String ip = getClientIp(request);
        if (!rateLimit.allow("login", ip)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail("Too many requests, please try again later"));
        }
        String username = str(body.get("username"));
        try {
            authService.requestPasswordReset(username);
            return ResponseEntity.ok(ApiResponse.ok(
                    "If the username exists and has a bound email, a reset code has been sent"));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.fail(e.getMessage()));
        }
    }

    /**
     * 确认密码重置：验证码校验 + 设置新密码。
     */
    @PostMapping("/api/password-reset/confirm")
    public ResponseEntity<ApiResponse> passwordResetConfirm(@RequestBody Map<String, Object> body,
                                                            HttpServletRequest request) {
        String ip = getClientIp(request);
        if (!rateLimit.allow("password_reset", ip)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail("Too many attempts, please try again later"));
        }
        String username = str(body.get("username"));
        String code = str(body.get("code"));
        String newPassword = str(body.get("new_password"));
        try {
            authService.confirmPasswordReset(username, code, newPassword);
            return ResponseEntity.ok(ApiResponse.ok("Password reset successfully"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    /**
     * 修改密码（需登录）。
     */
    @PostMapping("/api/user/change-password")
    public ResponseEntity<ApiResponse> changePassword(@RequestBody Map<String, Object> body,
                                                      @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        String oldPassword = str(body.get("old_password"));
        String newPassword = str(body.get("new_password"));
        try {
            authService.changePassword(principal.getUsername(), oldPassword, newPassword);
            return ResponseEntity.ok(ApiResponse.ok("Password changed successfully"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    // ---------- 辅助 ----------

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }

    /** 获取客户端 IP（对齐 Python cloudflare.get_client_ip，支持 X-Forwarded-For） */
    private static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp.trim();
        return request.getRemoteAddr();
    }
}

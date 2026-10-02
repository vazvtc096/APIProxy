package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 用户 Controller：当前用户信息 / 注销账号 / 设置。
 *
 * 对应 Python routes/user.py 的端点：
 * - GET  /userinfo
 * - POST /api/user/delete
 * - POST /api/user/settings（最大会话数）
 */
@RestController
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    /** 当前登录用户信息 */
    @GetMapping("/userinfo")
    public ResponseEntity<ApiResponse> userinfo(@AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        Map<String, Object> info = userService.getUserInfo(principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(info));
    }

    /** 注销账号（需密码确认，级联删除好友/会话/充值/流水） */
    @PostMapping("/api/user/delete")
    public ResponseEntity<ApiResponse> deleteAccount(@RequestBody Map<String, Object> body,
                                                      @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        String password = body.get("password") == null ? "" : body.get("password").toString();
        try {
            userService.deleteAccount(principal.getUsername(), password);
            return ResponseEntity.ok(ApiResponse.ok("Account deleted successfully"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiResponse.fail(e.getMessage()));
        }
    }

    /** 更新用户设置（最大会话数 1-5） */
    @PostMapping("/api/user/settings")
    public ResponseEntity<ApiResponse> updateSettings(@RequestBody Map<String, Object> body,
                                                      @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        Object ms = body.get("max_sessions");
        if (ms == null) {
            return ResponseEntity.badRequest().body(ApiResponse.fail("max_sessions required"));
        }
        try {
            int maxSessions = Integer.parseInt(ms.toString());
            userService.updateMaxSessions(principal.getUsername(), maxSessions);
            return ResponseEntity.ok(ApiResponse.ok("Settings updated"));
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail("max_sessions must be an integer"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }
}

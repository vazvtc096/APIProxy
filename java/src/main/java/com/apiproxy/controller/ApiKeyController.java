package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.ApiKeyService;
import com.apiproxy.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * API Key Controller：生成 / 列表 / 删除。
 *
 * 对应 Python routes/user.py 中的 API Key 管理端点（已登录用户，无需密码验证）：
 * - POST   /api/user/apikeys      生成新 API Key（返回明文，仅此一次）
 * - GET    /api/user/apikeys      列出当前用户所有 API Key（元数据）
 * - DELETE /api/user/apikeys/{key} 删除指定 API Key
 */
@RestController
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final RateLimitService rateLimit;

    public ApiKeyController(ApiKeyService apiKeyService, RateLimitService rateLimit) {
        this.apiKeyService = apiKeyService;
        this.rateLimit = rateLimit;
    }

    /**
     * 生成新 API Key。
     * 返回明文 Key（仅此一次，后续无法恢复），对齐 Python APIKey._require_apikey_trusted。
     */
    @PostMapping("/api/user/apikeys")
    public ResponseEntity<ApiResponse> generateApiKey(@AuthenticationPrincipal CustomUserDetails principal,
                                                      HttpServletRequest request) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }

        // 限流（按用户维度）
        String rateKey = principal.getUsername();
        if (!rateLimit.allow("login", rateKey)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail("Too many requests, please try again later"));
        }

        try {
            String newKey = apiKeyService.generateApiKey(principal.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.ok("API key generated", Map.of("api_key", newKey)));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.fail(e.getMessage()));
        } catch (IllegalStateException e) {
            // 超过上限或生成失败
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.fail(e.getMessage()));
        }
    }

    /**
     * 列出当前用户的所有 API Key（元数据，不含明文 Key）。
     */
    @GetMapping("/api/user/apikeys")
    public ResponseEntity<ApiResponse> listApiKeys(@AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        List<Map<String, Object>> keys = apiKeyService.listApiKeys(principal.getUsername());
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("apikeys", keys);
        data.put("total", keys.size());
        return ResponseEntity.ok(ApiResponse.ok(data));
    }

    /**
     * 删除指定 API Key。
     * 仅允许 Key 所属用户删除。
     */
    @DeleteMapping("/api/user/apikeys/{key}")
    public ResponseEntity<ApiResponse> deleteApiKey(@PathVariable("key") String apiKey,
                                                    @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }
        boolean deleted = apiKeyService.deleteApiKey(principal.getUsername(), apiKey);
        if (!deleted) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.fail("API key not found or does not belong to you"));
        }
        return ResponseEntity.ok(ApiResponse.ok("API key deleted successfully"));
    }
}

package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.service.EmailCaptchaService;
import com.apiproxy.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 邮箱验证码 Controller。
 *
 * 对应 Python routes/email_captcha.py：
 * - POST /api/email/send-code     发送验证码
 * - POST /api/email/verify-code   校验验证码
 */
@RestController
public class EmailCaptchaController {

    private final EmailCaptchaService captchaService;
    private final RateLimitService rateLimit;

    public EmailCaptchaController(EmailCaptchaService captchaService,
                                   RateLimitService rateLimit) {
        this.captchaService = captchaService;
        this.rateLimit = rateLimit;
    }

    /** 发送验证码 */
    @PostMapping("/api/email/send-code")
    public ResponseEntity<ApiResponse> sendCode(@RequestBody Map<String, Object> body,
                                                 HttpServletRequest request) {
        String ip = getClientIp(request);
        if (!rateLimit.allow("email_captcha", ip)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail("Too many requests, please try again later"));
        }
        String email = str(body.get("email"));
        String purpose = str(body.get("purpose"));
        if (purpose.isBlank()) purpose = "register";
        try {
            captchaService.sendCode(email, purpose);
            return ResponseEntity.ok(ApiResponse.ok("Verification code sent"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail(e.getMessage()));
        }
    }

    /** 校验验证码 */
    @PostMapping("/api/email/verify-code")
    public ResponseEntity<ApiResponse> verifyCode(@RequestBody Map<String, Object> body) {
        String email = str(body.get("email"));
        String code = str(body.get("code"));
        boolean ok = captchaService.verifyOnly(email, code);
        if (ok) {
            return ResponseEntity.ok(ApiResponse.ok("Code verified"));
        }
        return ResponseEntity.badRequest().body(ApiResponse.fail("Invalid or expired code"));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }

    private static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp.trim();
        return request.getRemoteAddr();
    }
}

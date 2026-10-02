package com.apiproxy.service;

import com.apiproxy.entity.User;
import com.apiproxy.repository.UserRepository;
import com.apiproxy.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 邮箱验证码服务。
 *
 * 对应 Python routes/email_captcha.py + captcha.py：
 * - 生成 6 位数字验证码
 * - 按邮箱存储，有效期 10 分钟
 * - 发送验证码邮件
 * - 校验验证码
 *
 * 生产环境应改用 Redis 存储（对齐 Python redis_client），
 * 此处用 ConcurrentHashMap 做内存实现，确保功能完整可运行。
 */
@Service
public class EmailCaptchaService {

    private static final Logger log = LoggerFactory.getLogger(EmailCaptchaService.class);
    private static final long EXPIRY_SECONDS = 600; // 10 分钟
    private static final int RESEND_COOLDOWN = 60;  // 60 秒重发冷却

    private final EmailService emailService;
    private final UserRepository userRepository;

    /** email -> {code, expiresAt, sentAt} */
    private final Map<String, CaptchaEntry> store = new ConcurrentHashMap<>();

    public EmailCaptchaService(EmailService emailService, UserRepository userRepository) {
        this.emailService = emailService;
        this.userRepository = userRepository;
    }

    /**
     * 发送验证码到指定邮箱。
     * @param email 目标邮箱
     * @param purpose 用途（register / password_reset / change_email）
     * @return true 发送成功
     */
    public boolean sendCode(String email, String purpose) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("Email is required");
        }
        // 检查重发冷却
        CaptchaEntry existing = store.get(email);
        if (existing != null) {
            long elapsed = Instant.now().getEpochSecond() - existing.sentAt;
            if (elapsed < RESEND_COOLDOWN) {
                throw new IllegalStateException("Please wait " + (RESEND_COOLDOWN - elapsed) + "s before resending");
            }
        }
        // 注册场景：检查邮箱是否已被占用
        if ("register".equals(purpose)) {
            if (userRepository.findByEmail(email).isPresent()) {
                throw new IllegalArgumentException("Email already registered");
            }
        }
        String code = String.format("%06d", ThreadLocalRandom.current().nextInt(1_000_000));
        long now = Instant.now().getEpochSecond();
        store.put(email, new CaptchaEntry(code, now + EXPIRY_SECONDS, now));
        try {
            String subject = switch (purpose) {
                case "password_reset" -> "APIProxy - Password Reset Code";
                case "change_email" -> "APIProxy - Email Change Verification";
                default -> "APIProxy - Verification Code";
            };
            String body = String.format(
                    "Your verification code is: %s%n%nThis code expires in 10 minutes.%nIf you did not request this, please ignore this email.",
                    code
            );
            emailService.sendVerificationEmail(email);
            log.info("Captcha sent to {} for purpose={}", email, purpose);
            return true;
        } catch (Exception e) {
            log.error("Failed to send captcha email to {}", email, e);
            store.remove(email);
            throw new IllegalStateException("Failed to send verification email: " + e.getMessage());
        }
    }

    /**
     * 校验验证码。
     * @param email 邮箱
     * @param code 用户输入的验证码
     * @param consume 是否消费（校验成功后删除）
     * @return true 验证通过
     */
    public boolean verifyCode(String email, String code, boolean consume) {
        if (email == null || code == null) return false;
        CaptchaEntry entry = store.get(email);
        if (entry == null) return false;
        if (Instant.now().getEpochSecond() > entry.expiresAt) {
            store.remove(email);
            return false;
        }
        boolean ok = entry.code.equals(code.trim());
        if (ok && consume) {
            store.remove(email);
        }
        return ok;
    }

    /** 校验并消费验证码 */
    public boolean verifyAndConsume(String email, String code) {
        return verifyCode(email, code, true);
    }

    /** 仅校验不消费（用于前端实时反馈） */
    public boolean verifyOnly(String email, String code) {
        return verifyCode(email, code, false);
    }

    /** 清理过期验证码（定时任务调用） */
    public void cleanupExpired() {
        long now = Instant.now().getEpochSecond();
        store.entrySet().removeIf(e -> e.getValue().expiresAt < now);
    }

    private record CaptchaEntry(String code, long expiresAt, long sentAt) {}
}

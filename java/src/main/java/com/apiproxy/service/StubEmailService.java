package com.apiproxy.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Service;

/**
 * 邮件服务桩实现：SMTP 未配置时使用。
 *
 * - isConfigured() 返回 false：注册走滑块验证码，密码重置直接拒绝
 * - 所有发送方法返回 false
 *
 * 当 application.yml 配置 spring.mail.host 时，应替换为 SmtpEmailService。
 */
@Service
@ConditionalOnMissingBean(name = "smtpEmailService")
public class StubEmailService implements EmailService {

    @Override
    public boolean isConfigured() {
        return false;
    }

    @Override
    public boolean verifyCode(String email, String code, String expectedType, String expectedUsername) {
        // SMTP 未配置：无验证码存储，一律拒绝
        return false;
    }

    @Override
    public boolean sendPasswordResetEmail(String email, String username) {
        return false;
    }

    @Override
    public boolean sendVerificationEmail(String email) {
        return false;
    }

    @Override
    public boolean sendLoginAlertEmail(String email, String username, String ip,
                                      String userAgent, String loginTime,
                                      String deviceType, String riskLevel, String riskDetails) {
        return false;
    }
}

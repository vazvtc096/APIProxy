package com.apiproxy.service;

/**
 * 邮件服务接口。
 *
 * 对应 Python email_utils.py：发送验证码 / 密码重置邮件 / 异地登录提醒。
 * 默认实现为 StubEmailService（SMTP 未配置时返回 isConfigured()=false，
 * 注册走滑块验证码兜底，密码重置返回未配置错误）。
 *
 * 真实 SMTP 实现见 SmtpEmailService（后续按 application.yml 配置注入）。
 */
public interface EmailService {

    /** SMTP 是否已配置（决定注册走邮箱验证还是滑块验证） */
    boolean isConfigured();

    /**
     * 验证邮箱验证码（对齐 Python email_utils.verify_code）。
     *
     * @param email           接收邮箱
     * @param code            用户输入的验证码
     * @param expectedType    期望类型（password_reset / register / login_alert），null 表示不限制
     * @param expectedUsername 绑定用户名（防跨账号复用），null 表示不限制
     * @return 验证通过返回 true
     */
    boolean verifyCode(String email, String code, String expectedType, String expectedUsername);

    /** 发送密码重置邮件（对齐 Python send_password_reset_email） */
    boolean sendPasswordResetEmail(String email, String username);

    /** 发送注册验证码 */
    boolean sendVerificationEmail(String email);

    /** 发送异地登录提醒邮件 */
    boolean sendLoginAlertEmail(String email, String username, String ip,
                                String userAgent, String loginTime,
                                String deviceType, String riskLevel, String riskDetails);
}

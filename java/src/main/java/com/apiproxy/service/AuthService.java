package com.apiproxy.service;

import com.apiproxy.entity.Friend;
import com.apiproxy.entity.User;
import com.apiproxy.repository.FriendRepository;
import com.apiproxy.repository.UserRepository;
import com.apiproxy.security.CompatiblePasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 认证服务：注册 / 密码重置 / 修改密码。
 *
 * 登录由 Spring Security + CustomUserDetailsService 处理，此处不实现。
 * 对应 Python routes/auth.py 的 register / password_reset_request / password_reset_confirm / change_password。
 *
 * 业务规则（对齐 Python 版）：
 * - 用户名只允许字母数字下划线，长度上限 32
 * - 密码至少 6 位，必须包含字母和数字
 * - 邮箱可选；SMTP 未配置时不存邮箱（防止冒用）
 * - 注册成功后自动与内置 admin 建立受保护好友关系（接收公告）
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private static final int MAX_USERNAME_LENGTH = 32;
    private static final int MIN_PASSWORD_LENGTH = 6;
    private static final Pattern SAFE_USERNAME = Pattern.compile("^[A-Za-z0-9_]+$");
    private static final Pattern EMAIL_FORMAT = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");

    private final UserRepository userRepository;
    private final FriendRepository friendRepository;
    private final CompatiblePasswordEncoder passwordEncoder;
    private final EmailService emailService;

    public AuthService(UserRepository userRepository,
                       FriendRepository friendRepository,
                       CompatiblePasswordEncoder passwordEncoder,
                       EmailService emailService) {
        this.userRepository = userRepository;
        this.friendRepository = friendRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
    }

    /**
     * 注册新用户。
     * @return 注册成功返回 UID；失败返回错误信息（throw IllegalArgumentException）
     */
    @Transactional
    public String register(String username, String password, String email, String code) {
        // 输入校验
        if (username == null || username.isBlank() || password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Username and password required");
        }
        username = username.trim();
        if (username.length() > MAX_USERNAME_LENGTH) {
            throw new IllegalArgumentException("Username too long (max " + MAX_USERNAME_LENGTH + " chars)");
        }
        if (!SAFE_USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("Username can only contain letters, numbers and underscores");
        }
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too short (min " + MIN_PASSWORD_LENGTH + " chars)");
        }
        if (!hasLetter(password)) {
            throw new IllegalArgumentException("Password must contain at least one letter");
        }
        if (!hasDigit(password)) {
            throw new IllegalArgumentException("Password must contain at least one digit");
        }

        // 邮箱验证分支
        if (emailService.isConfigured() && email != null && !email.isBlank()) {
            email = email.trim();
            if (!EMAIL_FORMAT.matcher(email).matches()) {
                throw new IllegalArgumentException("Invalid email format");
            }
            if (code == null || code.isBlank()) {
                throw new IllegalArgumentException("Verification code required");
            }
            if (!emailService.verifyCode(email, code, null, null)) {
                throw new IllegalArgumentException("Invalid verification code");
            }
            if (userRepository.findByEmail(email).isPresent()) {
                throw new IllegalArgumentException("Email already registered");
            }
        } else {
            // SMTP 未配置：不存邮箱，防止未验证邮箱被冒用
            email = null;
        }

        // 用户名唯一性检查（模糊提示防枚举）
        if (userRepository.findByUserName(username).isPresent()) {
            throw new IllegalArgumentException("This username is unavailable, please choose another");
        }

        // 生成密码哈希和 UID
        String passwordHash = passwordEncoder.encode(password);
        String uid = generateUid();

        User user = new User();
        user.setUserName(username);
        user.setUserPassword(passwordHash);
        user.setBalence(0.0);
        user.setUid(uid);
        user.setEmail(email);
        user.setIsAdmin(0);
        user.setIsBanned(0);
        user.setMaxSessions(1);
        user.setMaxOverdraft(0.0);
        user.setMustChangePassword(0);
        user.setLoginCount(0);
        user.setTotalSpent(0.0);
        user = userRepository.save(user);

        // 与内置 admin 建立受保护好友关系（接收通知/公告）
        try {
            ensureAdminFriendship(uid, username);
        } catch (Exception e) {
            log.error("ensureAdminFriendship failed for {}: {}", username, e.getMessage());
        }

        log.info("User registered: {} (uid={})", username, uid);
        return uid;
    }

    /**
     * 请求密码重置：发送验证码到绑定邮箱。
     * 无论用户是否存在都返回相同提示（防用户名枚举）。
     */
    @Transactional
    public void requestPasswordReset(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Username required");
        }
        username = username.trim();
        Optional<User> opt = userRepository.findByUserName(username);
        if (opt.isEmpty() || opt.get().getEmail() == null || opt.get().getEmail().isBlank()) {
            // 用户不存在或无邮箱：静默返回，不泄露信息
            return;
        }
        if (!emailService.isConfigured()) {
            throw new IllegalStateException("Email service not configured");
        }
        User user = opt.get();
        boolean ok = emailService.sendPasswordResetEmail(user.getEmail(), username);
        if (!ok) {
            throw new IllegalStateException("Failed to send reset email");
        }
        log.info("Password reset email sent to user: {}", username);
    }

    /**
     * 确认密码重置：验证码校验 + 设置新密码。
     */
    @Transactional
    public void confirmPasswordReset(String username, String code, String newPassword) {
        if (username == null || username.isBlank() || code == null || code.isBlank() || newPassword == null || newPassword.isEmpty()) {
            throw new IllegalArgumentException("Username, code and new password required");
        }
        username = username.trim();
        if (newPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too short (min " + MIN_PASSWORD_LENGTH + " chars)");
        }
        if (!hasLetter(newPassword) || !hasDigit(newPassword)) {
            throw new IllegalArgumentException("Password must contain letters and digits");
        }
        Optional<User> opt = userRepository.findByUserName(username);
        if (opt.isEmpty() || opt.get().getEmail() == null) {
            throw new IllegalArgumentException("Invalid username or code");
        }
        User user = opt.get();
        // 验证码绑定类型和用户名，防跨用途/跨账号复用
        if (!emailService.verifyCode(user.getEmail(), code, "password_reset", username)) {
            throw new IllegalArgumentException("Invalid or expired verification code");
        }
        user.setUserPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        log.info("Password reset successful: {}", username);
    }

    /**
     * 修改密码（需登录用户）。
     */
    @Transactional
    public void changePassword(String username, String oldPassword, String newPassword) {
        if (oldPassword == null || oldPassword.isEmpty() || newPassword == null || newPassword.isEmpty()) {
            throw new IllegalArgumentException("Old and new password required");
        }
        if (newPassword.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too short (min " + MIN_PASSWORD_LENGTH + " chars)");
        }
        if (!hasLetter(newPassword) || !hasDigit(newPassword)) {
            throw new IllegalArgumentException("Password must contain letters and digits");
        }
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        if (!passwordEncoder.matches(oldPassword, user.getUserPassword())) {
            throw new IllegalArgumentException("Old password incorrect");
        }
        user.setUserPassword(passwordEncoder.encode(newPassword));
        user.setMustChangePassword(0);
        userRepository.save(user);
        log.info("Password changed for user: {}", username);
    }

    /** 检查当前用户是否需要强制改密 */
    public boolean mustChangePassword(String username) {
        return userRepository.findByUserName(username)
                .map(u -> u.getIsAdmin() != null && u.getIsAdmin() == 1
                        && u.getMustChangePassword() != null && u.getMustChangePassword() == 1)
                .orElse(false);
    }

    // ---------- 内部辅助 ----------

    /** 与内置 admin 建立受保护好友关系（对齐 announcements.ensure_admin_friendship） */
    private void ensureAdminFriendship(String uid, String username) {
        // admin 用户约定为 user_name='admin'，uid 在系统初始化时写入
        User admin = userRepository.findByUserName("admin").orElse(null);
        if (admin == null || admin.getUid() == null) return;
        // 双向好友，标记 is_protected=1（不可删除）
        saveProtectedFriend(uid, admin.getUid(), admin.getUserName());
        saveProtectedFriend(admin.getUid(), uid, username);
    }

    private void saveProtectedFriend(String userUid, String friendUid, String friendName) {
        // 避免重复（已存在则跳过）
        if (friendRepository.findByUserUidAndStatus(userUid, "accepted").stream()
                .anyMatch(f -> friendUid.equals(f.getFriendUid()))) {
            return;
        }
        Friend f = new Friend();
        f.setUserUid(userUid);
        f.setFriendUid(friendUid);
        f.setFriendName(friendName);
        f.setStatus("accepted");
        f.setIsProtected(1);
        f.setCreatedAt(LocalDateTime.now());
        f.setAcceptedAt(LocalDateTime.now());
        friendRepository.save(f);
    }

    private static String generateUid() {
        // 12 位十六进制（对齐 Python generate_uid: uuid4().hex[:12]）
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    private static boolean hasLetter(String s) {
        for (char c : s.toCharArray()) if (Character.isLetter(c)) return true;
        return false;
    }

    private static boolean hasDigit(String s) {
        for (char c : s.toCharArray()) if (Character.isDigit(c)) return true;
        return false;
    }
}

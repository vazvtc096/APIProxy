package com.apiproxy.service;

import com.apiproxy.entity.User;
import com.apiproxy.repository.BalenceTransactionRepository;
import com.apiproxy.repository.FriendRepository;
import com.apiproxy.repository.RechargeRequestRepository;
import com.apiproxy.repository.SessionRepository;
import com.apiproxy.repository.UserRepository;
import com.apiproxy.security.CompatiblePasswordEncoder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

/**
 * 用户服务：查询信息 / 注销账号 / 设置。
 *
 * 对应 Python routes/user.py 的 /userinfo 和 /api/user/delete。
 *
 * 注销账号级联删除（硬约束，避免孤儿数据）：
 * - sessions（会话）
 * - friends（好友关系，双向）
 * - recharge_requests（充值请求）
 * - balence_transactions（余额流水）
 * - users（用户记录本身）
 * 管理员账号禁止注销。
 */
@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final FriendRepository friendRepository;
    private final RechargeRequestRepository rechargeRepository;
    private final BalenceTransactionRepository transactionRepository;
    private final CompatiblePasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                      SessionRepository sessionRepository,
                      FriendRepository friendRepository,
                      RechargeRequestRepository rechargeRepository,
                      BalenceTransactionRepository transactionRepository,
                      CompatiblePasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.sessionRepository = sessionRepository;
        this.friendRepository = friendRepository;
        this.rechargeRepository = rechargeRepository;
        this.transactionRepository = transactionRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * 获取当前登录用户信息。
     * 对齐 Python /userinfo：返回基本信息、余额、API keys 数量、管理员/封禁状态。
     */
    public Map<String, Object> getUserInfo(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalStateException("User not found: " + username));
        Map<String, Object> info = new HashMap<>();
        info.put("user_name", user.getUserName());
        info.put("uid", user.getUid());
        info.put("email", user.getEmail() == null ? "" : user.getEmail());
        info.put("balence", user.getBalence() == null ? 0.0 : user.getBalence());
        info.put("total_spent", user.getTotalSpent() == null ? 0.0 : user.getTotalSpent());
        info.put("is_admin", user.getIsAdmin() != null && user.getIsAdmin() == 1);
        info.put("is_banned", user.getIsBanned() != null && user.getIsBanned() == 1);
        info.put("ban_reason", user.getBanReason() == null ? "" : user.getBanReason());
        // apikeys 字段存储逗号分隔的明文列表（历史遗留）；仅返回数量，不泄露明文
        String apikeys = user.getApikeys();
        int keyCount = (apikeys == null || apikeys.isBlank()) ? 0
                : (int) java.util.Arrays.stream(apikeys.split(","))
                        .filter(s -> !s.isBlank()).count();
        info.put("apikey_count", keyCount);
        info.put("max_sessions", user.getMaxSessions() == null ? 1 : user.getMaxSessions());
        info.put("login_count", user.getLoginCount() == null ? 0 : user.getLoginCount());
        info.put("last_active_time", user.getLastActiveTime() == null ? "" : user.getLastActiveTime());
        return info;
    }

    /**
     * 注销账号。
     * 对齐 Python /api/user/delete：密码校验 + 禁止删除管理员 + 级联清理。
     */
    @Transactional
    public void deleteAccount(String username, String password) {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password required");
        }
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        // 管理员禁止注销
        if (user.getIsAdmin() != null && user.getIsAdmin() == 1) {
            throw new IllegalStateException("Admin accounts cannot be deleted");
        }
        // 密码校验
        if (!passwordEncoder.matches(password, user.getUserPassword())) {
            throw new IllegalArgumentException("Password incorrect");
        }
        String uid = user.getUid();
        // 级联删除（顺序：会话 → 好友 → 充值 → 流水 → 用户）
        try {
            sessionRepository.deleteByUserName(username);
        } catch (Exception e) {
            log.warn("delete sessions for {} failed: {}", username, e.getMessage());
        }
        try {
            friendRepository.deleteAllByUserUidOrFriendUid(uid);
        } catch (Exception e) {
            log.warn("delete friends for {} failed: {}", uid, e.getMessage());
        }
        try {
            rechargeRepository.deleteByUserUid(uid);
        } catch (Exception e) {
            log.warn("delete recharge requests for {} failed: {}", uid, e.getMessage());
        }
        try {
            transactionRepository.deleteByUserUid(uid);
        } catch (Exception e) {
            log.warn("delete transactions for {} failed: {}", uid, e.getMessage());
        }
        userRepository.delete(user);
        log.info("Account deleted: {} (uid={})", username, uid);
    }

    /**
     * 更新用户设置（最大会话数等）。
     */
    @Transactional
    public void updateMaxSessions(String username, int maxSessions) {
        if (maxSessions < 1 || maxSessions > 5) {
            throw new IllegalArgumentException("max_sessions must be between 1 and 5");
        }
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setMaxSessions(maxSessions);
        userRepository.save(user);
    }
}

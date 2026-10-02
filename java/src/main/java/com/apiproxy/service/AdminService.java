package com.apiproxy.service;

import com.apiproxy.entity.*;
import com.apiproxy.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 管理后台服务。
 *
 * 对应 Python routes/admin.py 的所有管理功能。
 * 字段对齐实际 Entity：User.userName / User.balence / User.isAdmin / User.isBanned 等。
 */
@Service
public class AdminService {

    private static final Logger log = LoggerFactory.getLogger(AdminService.class);

    private final UserRepository userRepository;
    private final AnnouncementRepository announcementRepository;
    private final IpBlacklistRepository ipBlacklistRepository;
    private final IpWhitelistRepository ipWhitelistRepository;
    private final DeviceBanRepository deviceBanRepository;
    private final HooksRepository hooksRepository;
    private final PostRepository postRepository;
    private final ScheduledTasksRepository scheduledTasksRepository;
    private final AuditLogRepository auditLogRepository;
    private final SystemConfigRepository systemConfigRepository;
    private final UpstreamRepository upstreamRepository;
    private final ModelPriceRepository modelPriceRepository;

    public AdminService(UserRepository userRepository,
                        AnnouncementRepository announcementRepository,
                        IpBlacklistRepository ipBlacklistRepository,
                        IpWhitelistRepository ipWhitelistRepository,
                        DeviceBanRepository deviceBanRepository,
                        HooksRepository hooksRepository,
                        PostRepository postRepository,
                        ScheduledTasksRepository scheduledTasksRepository,
                        AuditLogRepository auditLogRepository,
                        SystemConfigRepository systemConfigRepository,
                        UpstreamRepository upstreamRepository,
                        ModelPriceRepository modelPriceRepository) {
        this.userRepository = userRepository;
        this.announcementRepository = announcementRepository;
        this.ipBlacklistRepository = ipBlacklistRepository;
        this.ipWhitelistRepository = ipWhitelistRepository;
        this.deviceBanRepository = deviceBanRepository;
        this.hooksRepository = hooksRepository;
        this.postRepository = postRepository;
        this.scheduledTasksRepository = scheduledTasksRepository;
        this.auditLogRepository = auditLogRepository;
        this.systemConfigRepository = systemConfigRepository;
        this.upstreamRepository = upstreamRepository;
        this.modelPriceRepository = modelPriceRepository;
    }

    // ---------- 仪表盘统计 ----------

    public Map<String, Object> getDashboardStats() {
        long total = userRepository.count();
        long banned = userRepository.findAll().stream().filter(u -> u.getIsBanned() != null && u.getIsBanned() == 1).count();
        return Map.of(
                "total_users", total,
                "active_users", total - banned,
                "banned_users", banned,
                "total_posts", postRepository.count(),
                "total_announcements", announcementRepository.count(),
                "blacklisted_ips", ipBlacklistRepository.count(),
                "total_hooks", hooksRepository.count()
        );
    }

    // ---------- 用户管理 ----------

    public Page<User> listUsers(int page, int size, String search) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "id"));
        if (search != null && !search.isBlank()) {
            // 简单过滤：在内存中筛选（数据量不大时可用）
            List<User> all = userRepository.findAll();
            List<User> filtered = all.stream()
                    .filter(u -> (u.getUserName() != null && u.getUserName().contains(search))
                            || (u.getEmail() != null && u.getEmail().contains(search)))
                    .toList();
            int start = (int) pr.getOffset();
            int end = Math.min(start + size, filtered.size());
            return new org.springframework.data.domain.PageImpl<>(
                    start < filtered.size() ? filtered.subList(start, end) : List.of(),
                    pr, filtered.size());
        }
        return userRepository.findAll(pr);
    }

    @Transactional
    public void banUser(String username, String reason, String adminUser) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setIsBanned(1);
        user.setBanReason(reason);
        userRepository.save(user);
        log.warn("Admin {} banned user {}: {}", adminUser, username, reason);
    }

    @Transactional
    public void unbanUser(String username, String adminUser) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setIsBanned(0);
        user.setBanReason(null);
        userRepository.save(user);
        log.info("Admin {} unbanned user {}", adminUser, username);
    }

    @Transactional
    public void setUserRole(String username, String role, String adminUser) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        user.setIsAdmin("admin".equalsIgnoreCase(role) ? 1 : 0);
        userRepository.save(user);
        log.info("Admin {} set role={} for user {}", adminUser, role, username);
    }

    // ---------- 公告管理 ----------

    public Page<Announcement> listAnnouncements(int page, int size) {
        return announcementRepository.findAll(
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @Transactional
    public Announcement createAnnouncement(String title, String content, String author, boolean pinned) {
        Announcement ann = new Announcement();
        ann.setAnnouncementId("ANN" + System.currentTimeMillis());
        ann.setTitle(title);
        ann.setContent(content);
        ann.setSenderName(author);
        ann.setPinned(pinned ? 1 : 0);
        ann.setCreatedAt(LocalDateTime.now());
        return announcementRepository.save(ann);
    }

    @Transactional
    public void deleteAnnouncement(Integer id) {
        announcementRepository.deleteById(id);
    }

    // ---------- IP 黑白名单 ----------

    public List<IpBlacklist> listBlacklistedIps() {
        return ipBlacklistRepository.findAll(Sort.by(Sort.Direction.DESC, "createdAt"));
    }

    @Transactional
    public void addBlacklistedIp(String ip, String reason, String adminUser) {
        if (ipBlacklistRepository.findByIp(ip).isPresent()) {
            throw new IllegalStateException("IP already blacklisted");
        }
        IpBlacklist entry = new IpBlacklist();
        entry.setIp(ip);
        entry.setReason(reason);
        entry.setCreatedAt(LocalDateTime.now());
        ipBlacklistRepository.save(entry);
        log.warn("Admin {} blacklisted IP {}: {}", adminUser, ip, reason);
    }

    @Transactional
    public void removeBlacklistedIp(String ip) {
        ipBlacklistRepository.findByIp(ip).ifPresent(ipBlacklistRepository::delete);
    }

    // ---------- 设备封禁 ----------

    public Page<DeviceBan> listDeviceBans(int page, int size) {
        return deviceBanRepository.findAll(
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    // ---------- Hooks 管理 ----------

    public Page<Hooks> listHooks(int page, int size) {
        return hooksRepository.findAll(
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    // ---------- 帖子管理 ----------

    public Page<Post> listPosts(int page, int size) {
        return postRepository.findAll(
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @Transactional
    public void deletePost(Integer postId, String adminUser) {
        postRepository.deleteById(postId);
        log.info("Admin {} deleted post {}", adminUser, postId);
    }

    // ---------- 定时任务管理 ----------

    public List<ScheduledTasks> listScheduledTasks() {
        return scheduledTasksRepository.findAll(Sort.by(Sort.Direction.ASC, "id"));
    }

    @Transactional
    public void toggleTask(Long taskId, boolean enabled) {
        ScheduledTasks task = scheduledTasksRepository.findById(taskId)
                .orElseThrow(() -> new IllegalArgumentException("Task not found"));
        task.setIsEnabled(enabled ? 1 : 0);
        scheduledTasksRepository.save(task);
    }

    // ---------- 审计日志 ----------

    public Page<AuditLog> listAuditLogs(int page, int size, String action, String username) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        if (action != null && !action.isBlank()) {
            List<AuditLog> all = auditLogRepository.findAll();
            List<AuditLog> filtered = all.stream()
                    .filter(l -> action.equals(l.getEventType()))
                    .toList();
            return paginate(filtered, pr);
        }
        if (username != null && !username.isBlank()) {
            List<AuditLog> all = auditLogRepository.findAll();
            List<AuditLog> filtered = all.stream()
                    .filter(l -> username.equals(l.getUserName()))
                    .toList();
            return paginate(filtered, pr);
        }
        return auditLogRepository.findAll(pr);
    }

    // ---------- 系统配置 ----------

    public List<SystemConfig> listSystemConfigs() {
        return systemConfigRepository.findAll(Sort.by(Sort.Direction.ASC, "key"));
    }

    @Transactional
    public void updateSystemConfig(String key, String value) {
        SystemConfig config = systemConfigRepository.findById(key)
                .orElseGet(() -> {
                    SystemConfig c = new SystemConfig();
                    c.setKey(key);
                    return c;
                });
        config.setValue(value);
        config.setUpdatedAt(LocalDateTime.now());
        systemConfigRepository.save(config);
    }

    // ---------- 上游节点 ----------

    public List<Upstream> listUpstreams() {
        return upstreamRepository.findAll(Sort.by(Sort.Direction.ASC, "priority"));
    }

    // ---------- 定价 ----------

    public List<ModelPrice> listModelPrices() {
        return modelPriceRepository.findAll(Sort.by(Sort.Direction.ASC, "model"));
    }

    // ---------- 工具 ----------

    private static <T> Page<T> paginate(List<T> list, PageRequest pr) {
        int start = (int) pr.getOffset();
        int end = Math.min(start + pr.getPageSize(), list.size());
        return new org.springframework.data.domain.PageImpl<>(
                start < list.size() ? list.subList(start, end) : List.of(),
                pr, list.size());
    }
}

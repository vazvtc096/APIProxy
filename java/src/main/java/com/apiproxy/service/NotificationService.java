package com.apiproxy.service;

import com.apiproxy.entity.Notifications;
import com.apiproxy.entity.User;
import com.apiproxy.repository.NotificationsRepository;
import com.apiproxy.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 站内通知服务（铃铛 / 公告收件箱）。
 *
 * 对应 Python notifications.py：add_notification / get_notifications / unread_count / mark_read。
 * 同时提供 /api/stream SSE 长连接的推送辅助（对齐 Python social.py unified_events_stream）：
 * 具名事件 unread（未读数）与 userinfo（用户名/UID/余额/管理员标记等），
 * 每 3 秒重算快照、仅变化时推送；每个用户维护一个 SseEmitter 注册表
 * （ConcurrentHashMap&lt;uid, List&lt;SseEmitter&gt;&gt;）。
 */
@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private static final long SSE_TIMEOUT_MS = 300_000L;   // 对齐 WebConfig 异步超时 5 分钟
    private static final long SSE_INTERVAL_SECONDS = 3L;   // 对齐 Python 每 3s 重算快照
    private static final Set<String> NOTIFICATION_LEVELS = Set.of("info", "warning", "critical");
    private static final DateTimeFormatter TS_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final NotificationsRepository notificationsRepository;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final ScheduledExecutorService scheduler;

    /** 每个用户的 SseEmitter 注册表（key = uid） */
    private final Map<String, List<SseEmitter>> emitterRegistry = new ConcurrentHashMap<>();
    /** 每个 emitter 上次推送的快照（用于仅在变化时推送） */
    private final Map<SseEmitter, EmitterState> emitterStates = new ConcurrentHashMap<>();

    public NotificationService(NotificationsRepository notificationsRepository,
                               UserRepository userRepository,
                               ObjectMapper objectMapper) {
        this.notificationsRepository = notificationsRepository;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "notification-sse");
            t.setDaemon(true);
            return t;
        });
    }

    // ==================== 通知 CRUD ====================

    /**
     * 给单个用户写入一条通知（对齐 Python add_notification）。
     * @param type 通知级别（info / warning / critical，非法值回落为 info）
     * @return 通知 id；失败返回 null（不阻断主流程）
     */
    @Transactional
    public String addNotification(String uid, String title, String content, String type) {
        if (uid == null || uid.isBlank()) return null;
        String level = (type != null && NOTIFICATION_LEVELS.contains(type)) ? type : "info";
        String t = truncate((title == null ? "" : title).trim(), 300);
        String b = truncate((content == null ? "" : content).trim(), 8000);
        Notifications n = new Notifications();
        n.setId("ntf_" + randomHex(14));
        n.setUserUid(uid);
        n.setTitle(t);
        n.setBody(b);
        n.setLevel(level);
        n.setIsRead(0);
        n.setCreatedAt(LocalDateTime.now().format(TS_FORMATTER));
        try {
            notificationsRepository.save(n);
            pushUnreadEvent(uid);   // 实时通知该用户的 SSE 订阅者
            return n.getId();
        } catch (Exception e) {
            log.error("addNotification failed for {}: {}", uid, e.getMessage());
            return null;
        }
    }

    /** 取某用户的通知列表（按时间倒序，支持仅未读与分页）。 */
    public List<Notifications> getNotifications(String uid, boolean unreadOnly, int limit, int offset) {
        if (uid == null || uid.isBlank()) return List.of();
        int lim = Math.min(Math.max(limit, 1), 100);
        int off = Math.max(offset, 0);
        try {
            if (unreadOnly) return notificationsRepository.findPageByUidUnread(uid, lim, off);
            return notificationsRepository.findPageByUid(uid, lim, off);
        } catch (Exception e) {
            log.error("getNotifications failed for {}: {}", uid, e.getMessage());
            return List.of();
        }
    }

    /** 未读通知数。 */
    public long unreadCount(String uid) {
        if (uid == null || uid.isBlank()) return 0;
        try {
            return notificationsRepository.countUnreadByUid(uid);
        } catch (Exception e) {
            log.error("unreadCount failed for {}: {}", uid, e.getMessage());
            return 0;
        }
    }

    /**
     * 标记已读（对齐 Python mark_read）。
     * @param all 为 true（或 id 为 null/"all"）时标记该用户全部已读；否则标记单条
     * @return 影响行数
     */
    @Transactional
    public int markRead(String uid, String id, boolean all) {
        if (uid == null || uid.isBlank()) return 0;
        try {
            int affected;
            if (all || id == null || id.isBlank() || "all".equalsIgnoreCase(id)) {
                affected = notificationsRepository.markAllReadByUid(uid);
            } else {
                affected = notificationsRepository.markReadByIdAndUid(id, uid);
            }
            pushUnreadEvent(uid);
            return affected;
        } catch (Exception e) {
            log.error("markRead failed for {}: {}", uid, e.getMessage());
            return 0;
        }
    }

    // ==================== SSE /api/stream ====================

    /**
     * 创建该用户的 SseEmitter 长连接（对应 GET /api/stream）：
     * 先推一次 unread / userinfo 快照，之后每 3 秒重算、仅变化时推送。
     * 客户端断开 / 超时后自动从注册表移除并停止推送。
     */
    public SseEmitter streamUserEvents(String uid) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        EmitterState state = new EmitterState();
        emitterStates.put(emitter, state);
        register(uid, emitter);

        try {
            sendUnread(uid, emitter, state);
            sendUserinfo(uid, emitter, state);
        } catch (Exception e) {
            log.debug("initial sse push failed for {}: {}", uid, e.getMessage());
        }

        AtomicReference<ScheduledFuture<?>> ref = new AtomicReference<>();
        Runnable task = () -> {
            try {
                sendUnread(uid, emitter, state);
                sendUserinfo(uid, emitter, state);
            } catch (Exception e) {
                log.debug("sse push failed for {}: {}", uid, e.getMessage());
                ScheduledFuture<?> f = ref.get();
                if (f != null) f.cancel(false);
                unregister(uid, emitter);
                emitterStates.remove(emitter);
            }
        };
        ScheduledFuture<?> future = scheduler.scheduleAtFixedRate(
                task, SSE_INTERVAL_SECONDS, SSE_INTERVAL_SECONDS, TimeUnit.SECONDS);
        ref.set(future);

        emitter.onCompletion(() -> {
            future.cancel(false);
            unregister(uid, emitter);
            emitterStates.remove(emitter);
        });
        emitter.onTimeout(() -> {
            future.cancel(false);
            unregister(uid, emitter);
            emitterStates.remove(emitter);
        });
        emitter.onError(t -> {
            future.cancel(false);
            unregister(uid, emitter);
            emitterStates.remove(emitter);
        });
        return emitter;
    }

    /** 向该用户所有在线 SSE 连接立即推送一次 unread 事件（通知新增/已读时调用） */
    private void pushUnreadEvent(String uid) {
        List<SseEmitter> emitters = emitterRegistry.get(uid);
        if (emitters == null || emitters.isEmpty()) return;
        for (SseEmitter emitter : emitters) {
            EmitterState state = emitterStates.get(emitter);
            if (state == null) continue;
            try {
                sendUnread(uid, emitter, state);
            } catch (Exception e) {
                log.debug("push unread event failed for {}: {}", uid, e.getMessage());
            }
        }
    }

    private void sendUnread(String uid, SseEmitter emitter, EmitterState state) throws Exception {
        long count = unreadCount(uid);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("unread_count", count);
        payload.put("total", count);
        String json = objectMapper.writeValueAsString(payload);
        if (json.equals(state.lastUnread)) return;   // 仅在变化时推送
        state.lastUnread = json;
        emitter.send(SseEmitter.event().name("unread").data(json));
    }

    /** userinfo 快照：形状对齐 Python _build_userinfo_payload 的关键字段 */
    private void sendUserinfo(String uid, SseEmitter emitter, EmitterState state) throws Exception {
        User user = userRepository.findByUid(uid).orElse(null);
        if (user == null) return;
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("username", user.getUserName());
        info.put("uid", user.getUid());
        info.put("balence", user.getBalence() == null ? 0.0 : user.getBalence());
        info.put("max_overdraft", user.getMaxOverdraft() == null ? 0 : user.getMaxOverdraft());
        info.put("created_at", user.getCreatedAt() == null ? "" : user.getCreatedAt());
        info.put("apikey_count", countApikeys(user.getApikeys()));
        info.put("is_admin", user.getIsAdmin() != null && user.getIsAdmin() == 1);
        info.put("must_change_password", user.getMustChangePassword() != null && user.getMustChangePassword() == 1);
        boolean banned = user.getIsBanned() != null && user.getIsBanned() == 1;
        info.put("is_banned", banned);
        info.put("ban_reason", banned ? (user.getBanReason() == null ? "" : user.getBanReason()) : "");
        String json = objectMapper.writeValueAsString(info);
        if (json.equals(state.lastUserinfo)) return;
        state.lastUserinfo = json;
        emitter.send(SseEmitter.event().name("userinfo").data(json));
    }

    private void register(String uid, SseEmitter emitter) {
        emitterRegistry.computeIfAbsent(uid, k -> new CopyOnWriteArrayList<>()).add(emitter);
    }

    private void unregister(String uid, SseEmitter emitter) {
        List<SseEmitter> list = emitterRegistry.get(uid);
        if (list != null) {
            list.remove(emitter);
            if (list.isEmpty()) emitterRegistry.remove(uid);
        }
    }

    // ==================== 内部辅助 ====================

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static int countApikeys(String apikeys) {
        if (apikeys == null || apikeys.isBlank()) return 0;
        int n = 0;
        for (String s : apikeys.split(",")) if (!s.isBlank()) n++;
        return n;
    }

    private static String randomHex(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append("0123456789abcdef".charAt(RANDOM.nextInt(16)));
        return sb.toString();
    }

    /** 每个 emitter 上次推送的快照（unread / userinfo 各一份，JSON 串） */
    private static final class EmitterState {
        volatile String lastUnread;
        volatile String lastUserinfo;
    }
}

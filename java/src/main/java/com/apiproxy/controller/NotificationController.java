package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.Notifications;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.NotificationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 通知 Controller（铃铛 / 公告收件箱）。
 *
 * 对应 Python routes/notifications_routes.py + social.py 的 /api/stream：
 * - GET  /api/notifications（列表 + 未读数，?limit=&unread=1 仅取未读）
 * - GET  /api/notifications/unread（仅未读数，供铃铛红点轮询）
 * - POST /api/notifications/read（body: {"id": "<nid>"} 标记单条；缺省 / id=all 标记全部）
 * - GET  /api/stream（SSE 长连接：具名事件 unread / userinfo）
 */
@RestController
public class NotificationController {

    private final NotificationService notificationService;

    public NotificationController(NotificationService notificationService) {
        this.notificationService = notificationService;
    }

    /** 通知列表 + 未读数。 */
    @GetMapping("/api/notifications")
    public ResponseEntity<ApiResponse> list(@RequestParam(defaultValue = "30") int limit,
                                            @RequestParam(defaultValue = "0") int offset,
                                            @RequestParam(defaultValue = "") String unread,
                                            @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.fail("Not logged in"));
        }
        boolean unreadOnly = "1".equals(unread) || "true".equalsIgnoreCase(unread);
        List<Notifications> items = notificationService.getNotifications(principal.getUid(), unreadOnly, limit, offset);
        List<Map<String, Object>> list = new ArrayList<>();
        for (Notifications n : items) list.add(toMap(n));
        long unreadCount = notificationService.unreadCount(principal.getUid());
        return ResponseEntity.ok(ApiResponse.ok(Map.of("notifications", list, "unread_count", unreadCount)));
    }

    /** 仅未读数（供铃铛红点高频轮询）。 */
    @GetMapping("/api/notifications/unread")
    public ResponseEntity<ApiResponse> unread(@AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.fail("Not logged in"));
        }
        long count = notificationService.unreadCount(principal.getUid());
        return ResponseEntity.ok(ApiResponse.ok(Map.of("unread_count", count)));
    }

    /** 标记已读：body {"id": "<nid>"} 标记单条；缺省或 id=all 标记全部。 */
    @PostMapping("/api/notifications/read")
    public ResponseEntity<ApiResponse> markRead(@RequestBody(required = false) Map<String, Object> body,
                                                @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiResponse.fail("Not logged in"));
        }
        Map<String, Object> data = body == null ? Map.of() : body;
        Object idObj = data.getOrDefault("id", "all");
        String id = idObj == null ? "all" : idObj.toString();
        boolean all = "all".equalsIgnoreCase(id);
        int affected = notificationService.markRead(principal.getUid(), id, all);
        long unreadCount = notificationService.unreadCount(principal.getUid());
        return ResponseEntity.ok(ApiResponse.ok(Map.of("success", true,
                "affected", affected, "unread_count", unreadCount)));
    }

    /**
     * 统一 SSE 长连接 /api/stream：具名事件 unread / userinfo。
     * 对齐 Python social.py unified_events_stream（GET 请求天然豁免 CSRF）。
     */
    @GetMapping("/api/stream")
    public SseEmitter stream(@AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            SseEmitter emitter = new SseEmitter();
            try {
                emitter.send(SseEmitter.event().name("error").data("Not logged in"));
            } catch (Exception e) {
                // ignore
            }
            emitter.complete();
            return emitter;
        }
        return notificationService.streamUserEvents(principal.getUid());
    }

    /** 通知实体 → snake_case JSON map（对齐 Python 返回字段） */
    private static Map<String, Object> toMap(Notifications n) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", n.getId());
        m.put("user_uid", n.getUserUid());
        m.put("title", n.getTitle() == null ? "" : n.getTitle());
        m.put("body", n.getBody() == null ? "" : n.getBody());
        m.put("level", n.getLevel() == null ? "info" : n.getLevel());
        m.put("link", n.getLink() == null ? "" : n.getLink());
        m.put("announcement_id", n.getAnnouncementId() == null ? "" : n.getAnnouncementId());
        m.put("is_read", n.getIsRead() == null ? 0 : n.getIsRead());
        m.put("created_at", n.getCreatedAt() == null ? "" : n.getCreatedAt());
        return m;
    }
}

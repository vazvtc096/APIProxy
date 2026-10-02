package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.ChatMessage;
import com.apiproxy.entity.Friend;
import com.apiproxy.entity.Post;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.SocialService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 社交 Controller。
 *
 * 对应 Python routes/social.py + social.py：
 *
 * 帖子：
 * - GET    /api/social/posts              帖子列表
 * - POST   /api/social/posts              发布帖子
 * - GET    /api/social/posts/{id}         帖子详情
 * - DELETE /api/social/posts/{id}         删除帖子
 * - POST   /api/social/posts/{id}/like    点赞
 * - POST   /api/social/posts/{id}/collect 收藏
 * - GET    /api/social/collections         我的收藏
 *
 * 好友：
 * - GET    /api/social/friends             好友列表
 * - GET    /api/social/friend-requests     好友请求
 * - POST   /api/social/friends/add         发送好友请求
 * - POST   /api/social/friends/accept      接受好友请求
 * - POST   /api/social/friends/reject      拒绝好友请求
 * - DELETE /api/social/friends/{username}  删除好友
 *
 * 私信：
 * - GET    /api/social/messages/{username} 获取对话
 * - POST   /api/social/messages             发送消息
 * - POST   /api/social/messages/read        标记已读
 *
 * 转账：
 * - POST   /api/social/transfer             转账
 * - GET    /api/social/transactions         交易记录
 */
@RestController
@RequestMapping("/api/social")
public class SocialController {

    private final SocialService socialService;

    public SocialController(SocialService socialService) {
        this.socialService = socialService;
    }

    // ---------- 帖子 ----------

    @GetMapping("/posts")
    public ResponseEntity<ApiResponse> listPosts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String category,
            @RequestParam(required = false) String username) {
        Page<Post> posts = socialService.listPosts(page, size, category, username);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", posts.getContent(),
                "total", posts.getTotalElements(),
                "page", posts.getNumber()
        )));
    }

    @PostMapping("/posts")
    public ResponseEntity<ApiResponse> createPost(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(ApiResponse.fail("Not logged in"));
        }
        String title = str(body.get("title"));
        String content = str(body.get("content"));
        String category = str(body.get("category"));
        Post post = socialService.createPost(principal.getUsername(), title, content, category);
        return ResponseEntity.ok(ApiResponse.ok("Post created", post));
    }

    @GetMapping("/posts/{id}")
    public ResponseEntity<ApiResponse> getPost(@PathVariable Integer id) {
        try {
            Post post = socialService.getPost(id);
            return ResponseEntity.ok(ApiResponse.ok(post));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/posts/{id}")
    public ResponseEntity<ApiResponse> deletePost(
            @PathVariable Integer id,
            @AuthenticationPrincipal CustomUserDetails principal) {
        try {
            socialService.deletePost(id, principal.getUsername());
            return ResponseEntity.ok(ApiResponse.ok("Post deleted"));
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(ApiResponse.fail(e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/posts/{id}/like")
    public ResponseEntity<ApiResponse> likePost(
            @PathVariable Integer id,
            @AuthenticationPrincipal CustomUserDetails principal) {
        socialService.toggleLike(id, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Like toggled"));
    }

    @PostMapping("/posts/{id}/collect")
    public ResponseEntity<ApiResponse> collectPost(
            @PathVariable Integer id,
            @AuthenticationPrincipal CustomUserDetails principal) {
        socialService.toggleCollection(id, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Collection toggled"));
    }

    @GetMapping("/collections")
    public ResponseEntity<ApiResponse> collections(
            @AuthenticationPrincipal CustomUserDetails principal) {
        List<Post> posts = socialService.getUserCollections(principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(posts));
    }

    // ---------- 好友 ----------

    @GetMapping("/friends")
    public ResponseEntity<ApiResponse> friends(
            @AuthenticationPrincipal CustomUserDetails principal) {
        List<Friend> friends = socialService.getFriends(principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(friends));
    }

    @GetMapping("/friend-requests")
    public ResponseEntity<ApiResponse> friendRequests(
            @AuthenticationPrincipal CustomUserDetails principal) {
        List<Friend> requests = socialService.getFriendRequests(principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(requests));
    }

    @PostMapping("/friends/add")
    public ResponseEntity<ApiResponse> addFriend(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String toUsername = str(body.get("username"));
        try {
            socialService.sendFriendRequest(principal.getUsername(), toUsername);
            return ResponseEntity.ok(ApiResponse.ok("Friend request sent"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/friends/accept")
    public ResponseEntity<ApiResponse> acceptFriend(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String fromUsername = str(body.get("username"));
        try {
            socialService.acceptFriendRequest(fromUsername, principal.getUsername());
            return ResponseEntity.ok(ApiResponse.ok("Friend request accepted"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/friends/reject")
    public ResponseEntity<ApiResponse> rejectFriend(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String fromUsername = str(body.get("username"));
        try {
            socialService.rejectFriendRequest(fromUsername, principal.getUsername());
            return ResponseEntity.ok(ApiResponse.ok("Friend request rejected"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @DeleteMapping("/friends/{username}")
    public ResponseEntity<ApiResponse> removeFriend(
            @PathVariable String username,
            @AuthenticationPrincipal CustomUserDetails principal) {
        socialService.removeFriend(principal.getUsername(), username);
        return ResponseEntity.ok(ApiResponse.ok("Friend removed"));
    }

    // ---------- 私信 ----------

    @GetMapping("/messages/{username}")
    public ResponseEntity<ApiResponse> messages(
            @PathVariable String username,
            @RequestParam(defaultValue = "50") int limit,
            @AuthenticationPrincipal CustomUserDetails principal) {
        List<ChatMessage> msgs = socialService.getConversation(
                principal.getUsername(), username, limit);
        return ResponseEntity.ok(ApiResponse.ok(msgs));
    }

    @PostMapping("/messages")
    public ResponseEntity<ApiResponse> sendMessage(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String toUsername = str(body.get("to"));
        String content = str(body.get("content"));
        try {
            ChatMessage msg = socialService.sendMessage(principal.getUsername(), toUsername, content);
            return ResponseEntity.ok(ApiResponse.ok("Message sent", msg));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/messages/read")
    public ResponseEntity<ApiResponse> markRead(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String fromUsername = str(body.get("from"));
        socialService.markAsRead(fromUsername, principal.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Messages marked as read"));
    }

    // ---------- 转账 ----------

    @PostMapping("/transfer")
    public ResponseEntity<ApiResponse> transfer(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        String toUsername = str(body.get("to"));
        double amount = Double.parseDouble(str(body.get("amount")));
        String note = str(body.get("note"));
        try {
            Map<String, Object> result = socialService.transferBalance(
                    principal.getUsername(), toUsername, amount, note);
            return ResponseEntity.ok(ApiResponse.ok("Transfer completed", result));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @GetMapping("/transactions")
    public ResponseEntity<ApiResponse> transactions(
            @AuthenticationPrincipal CustomUserDetails principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        var txs = socialService.getUserTransactions(principal.getUsername(), page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", txs.getContent(),
                "total", txs.getTotalElements()
        )));
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

package com.apiproxy.controller;

import com.apiproxy.entity.Announcement;
import com.apiproxy.entity.User;
import com.apiproxy.repository.AnnouncementRepository;
import com.apiproxy.repository.UserRepository;
import com.apiproxy.security.CustomUserDetails;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;

/**
 * 页面渲染 Controller（Thymeleaf 服务端渲染）。
 *
 * 对应 Python routes/pages.py 的所有页面路由：
 * - /, /login, /register, /forgot-password       公开页
 * - /dashboard, /settings, /docs, /docs/{page}    用户页
 * - /admin/**                                       管理后台页
 * - /social/**, /community, /friends               社交页
 * - /rcon/login, /rcon/terminal                    RCON 页
 * - /oauth/**                                       OAuth 页
 */
@Controller
public class PagesController {

    private final AnnouncementRepository announcementRepository;
    private final UserRepository userRepository;

    public PagesController(AnnouncementRepository announcementRepository,
                           UserRepository userRepository) {
        this.announcementRepository = announcementRepository;
        this.userRepository = userRepository;
    }

    // ---------- 公开页 ----------

    @GetMapping("/")
    public String index() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/forgot-password")
    public String forgotPassword() {
        return "forgot_password";
    }

    // ---------- 用户页 ----------

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal CustomUserDetails principal, Model model) {
        if (principal != null) {
            model.addAttribute("username", principal.getUsername());
            model.addAttribute("isAdmin", principal.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
        }
        List<Announcement> announcements = announcementRepository.findAll(
                Sort.by(Sort.Direction.DESC, "createdAt"));
        if (announcements.size() > 5) announcements = announcements.subList(0, 5);
        model.addAttribute("announcements", announcements);
        return "dashboard";
    }

    @GetMapping("/settings")
    public String settings(@AuthenticationPrincipal CustomUserDetails principal, Model model) {
        if (principal != null) {
            User user = userRepository.findByUserName(principal.getUsername()).orElse(null);
            model.addAttribute("user", user);
        }
        return "settings";
    }

    @GetMapping("/docs")
    public String docsHub() {
        return "docs_hub";
    }

    @GetMapping("/docs/{page}")
    public String docPage(@PathVariable String page, Model model) {
        model.addAttribute("docPage", page);
        return "doc_page";
    }

    // ---------- 管理后台页 ----------

    @GetMapping("/admin")
    public String adminIndex() {
        return "redirect:/admin/dashboard";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard() {
        return "admin_dashboard";
    }

    @GetMapping("/admin/users")
    public String adminUsers() {
        return "admin_users";
    }

    @GetMapping("/admin/announcements")
    public String adminAnnouncements() {
        return "admin_announcements";
    }

    @GetMapping("/admin/bans")
    public String adminBans() {
        return "admin_bans";
    }

    @GetMapping("/admin/hooks")
    public String adminHooks() {
        return "admin_hooks";
    }

    @GetMapping("/admin/posts")
    public String adminPosts() {
        return "admin_posts";
    }

    @GetMapping("/admin/tasks")
    public String adminTasks() {
        return "admin_tasks";
    }

    @GetMapping("/admin/audit")
    public String adminAudit() {
        return "admin_audit";
    }

    // ---------- 社交页 ----------

    @GetMapping("/community")
    public String community() {
        return "community";
    }

    @GetMapping("/friends")
    public String friends() {
        return "friends";
    }

    @GetMapping("/social/chat")
    public String socialChat() {
        return "social_chat";
    }

    @GetMapping("/social/posts")
    public String socialPosts() {
        return "social_posts";
    }

    @GetMapping("/social/create-post")
    public String socialCreatePost() {
        return "social_create_post";
    }

    @GetMapping("/social/post/{id}")
    public String socialPostDetail(@PathVariable Long id, Model model) {
        model.addAttribute("postId", id);
        return "social_post_detail";
    }

    @GetMapping("/social/collections")
    public String socialCollections() {
        return "social_collections";
    }

    @GetMapping("/social/friends")
    public String socialFriends() {
        return "social_friends";
    }

    @GetMapping("/social/friend-requests")
    public String socialFriendRequests() {
        return "social_friend_requests";
    }

    @GetMapping("/social/transactions")
    public String socialTransactions() {
        return "social_transactions";
    }

    @GetMapping("/social/transfer")
    public String socialTransfer() {
        return "social_transfer";
    }

    // ---------- RCON 页 ----------

    @GetMapping("/rcon/login")
    public String rconLogin() {
        return "rcon/login";
    }

    @GetMapping("/rcon/terminal")
    public String rconTerminal() {
        return "rcon/terminal";
    }

    // ---------- OAuth 页 ----------

    @GetMapping("/oauth/consent")
    public String oauthConsent() {
        return "oauth_consent";
    }

    @GetMapping("/oauth/device")
    public String oauthDevice() {
        return "oauth_device";
    }

    @GetMapping("/oauth/login")
    public String oauthLogin() {
        return "oauth_login";
    }

    @GetMapping("/oauth/callback")
    public String oauthCallback() {
        return "oauth_callback";
    }

    // ---------- 通知页 ----------

    @GetMapping("/notifications")
    public String notifications() {
        return "notifications";
    }

    // ---------- 聊天页 ----------

    @GetMapping("/chat")
    public String chat() {
        return "chat";
    }
}

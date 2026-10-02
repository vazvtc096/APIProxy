package com.apiproxy.config;

import com.apiproxy.security.webfilter.WebFilterInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Web MVC 配置：页面跳转 + 异步支持（SSE/长连接）+ 拦截器。
 *
 * 对应 Python routes/pages.py 的页面路由 + application.py 的 ASGI 异步
 * + web_filter.py 的 before/after_request 行为审计。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final WebFilterInterceptor webFilterInterceptor;

    public WebConfig(WebFilterInterceptor webFilterInterceptor) {
        this.webFilterInterceptor = webFilterInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(webFilterInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/static/**", "/css/**", "/js/**", "/img/**", "/favicon.ico");
    }

    /** 视图控制器：纯页面跳转（无业务逻辑） */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        // 公开页面
        registry.addViewController("/").setViewName("login");
        registry.addViewController("/login").setViewName("login");
        registry.addViewController("/register").setViewName("register");
        registry.addViewController("/forgot-password").setViewName("forgot_password");
        // 需登录的页面
        registry.addViewController("/dashboard").setViewName("dashboard");
        registry.addViewController("/settings").setViewName("settings");
        registry.addViewController("/chat").setViewName("chat");
        registry.addViewController("/community").setViewName("community");
        registry.addViewController("/friends").setViewName("friends");
        registry.addViewController("/notifications").setViewName("notifications");
        registry.addViewController("/docs").setViewName("docs_hub");
        // 社交模块页面
        registry.addViewController("/social/chat").setViewName("social_chat");
        registry.addViewController("/social/collections").setViewName("social_collections");
        registry.addViewController("/social/create-post").setViewName("social_create_post");
        registry.addViewController("/social/friend-requests").setViewName("social_friend_requests");
        registry.addViewController("/social/friends").setViewName("social_friends");
        registry.addViewController("/social/posts").setViewName("social_posts");
        registry.addViewController("/social/transactions").setViewName("social_transactions");
        registry.addViewController("/social/transfer").setViewName("social_transfer");
        // OAuth 页面
        registry.addViewController("/oauth/login").setViewName("oauth_login");
        registry.addViewController("/oauth/consent").setViewName("oauth_consent");
        registry.addViewController("/oauth/device").setViewName("oauth_device");
        registry.addViewController("/oauth/callback").setViewName("oauth_callback");
        // RCON 页面
        registry.addViewController("/rcon/terminal").setViewName("rcon/terminal");
        // 管理员页面
        registry.addViewController("/admin/announcements").setViewName("admin_announcements");
        registry.addViewController("/admin/bans").setViewName("admin_bans");
        registry.addViewController("/admin/hooks").setViewName("admin_hooks");
        registry.addViewController("/admin/posts").setViewName("admin_posts");
        registry.addViewController("/admin/tasks").setViewName("admin_tasks");
    }

    /** 异步请求配置：SSE 流式响应需要更长的超时 */
    @Override
    public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
        configurer.setDefaultTimeout(300_000L);
    }
}

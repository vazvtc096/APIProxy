package com.apiproxy.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * 安全上下文工具：从 SecurityContextHolder 获取当前登录用户。
 *
 * 对应 Python session['user'] 的获取语义。Spring Security 中，
 * 认证后的 principal 即 CustomUserDetails 实例。
 */
@Component
public class SecurityUtils {

    /**
     * 获取当前登录用户的 CustomUserDetails。
     *
     * @return 当前用户的 CustomUserDetails，未认证或匿名访问时返回 null
     */
    public CustomUserDetails getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof CustomUserDetails customUserDetails) {
            return customUserDetails;
        }
        return null;
    }
}

package com.apiproxy.security.webfilter;

import com.apiproxy.security.CustomUserDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * WebFilter 拦截器。
 *
 * 对应 Python web_filter.py 的 before_request / after_request 编排：
 * - preHandle: 分类检测 + 拦截
 * - afterCompletion: 行为审计（写入 web_access_log）
 */
@Component
public class WebFilterInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(WebFilterInterceptor.class);

    private final WebFilterService webFilterService;

    public WebFilterInterceptor(WebFilterService webFilterService) {
        this.webFilterService = webFilterService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        boolean isAdmin = isCurrentUserAdmin();
        WebFilterService.InspectResult result = webFilterService.inspectRequest(request, isAdmin);
        if (result.blocked) {
            log.warn("WebFilter blocked {} {}: {} ({})",
                    request.getMethod(), request.getRequestURI(), result.reason, result.category);
            response.setStatus(result.status);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(String.format(
                    "{\"success\":false,\"message\":\"%s\",\"category\":\"%s\"}",
                    result.reason.replace("\"", "\\\""), result.category));
            return false;
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        String clientIp = getClientIp(request);
        String username = getCurrentUsername();
        int status = response.getStatus();
        long bytes = 0; // 响应字节数在 Servlet 层不易精确获取，留 0
        webFilterService.recordAccess(request, clientIp, username, status, bytes);
    }

    private boolean isCurrentUserAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return false;
        return auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    private String getCurrentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof CustomUserDetails ud) {
            return ud.getUsername();
        }
        return null;
    }

    private static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String cfIp = request.getHeader("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isBlank()) return cfIp.trim();
        return request.getRemoteAddr();
    }
}

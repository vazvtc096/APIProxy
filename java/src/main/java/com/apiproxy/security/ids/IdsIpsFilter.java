package com.apiproxy.security.ids;

import com.apiproxy.security.waf.WafFilter;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * IDS/IPS Servlet Filter。
 *
 * 对应 Python __main__.py 中编排的 IDS/IPS 检查：
 * - 签名型攻击检测（Log4j/RCE/SSTI/SSRF/NoSQL/XXE/WebShell 等）
 * - 行为型检测（404 枚举、认证暴破）由 Interceptor/Controller 层调用 record404/recordAuthFailure
 * - block 模式下命中即拦截，detect 模式仅记录
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class IdsIpsFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(IdsIpsFilter.class);

    private final IdsIpsService idsIpsService;

    public IdsIpsFilter(IdsIpsService idsIpsService) {
        this.idsIpsService = idsIpsService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest) ||
            !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        // 从 WAF Filter 的缓存请求体中获取（如果已被包装）
        String body = null;
        ServletRequest actualRequest = request;
        if (request instanceof WafFilter.CachedBodyHttpServletRequest cached) {
            byte[] bodyBytes = cached.getCachedBody();
            if (bodyBytes != null && bodyBytes.length > 0) {
                body = new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
            }
        }

        String clientIp = getClientIp(httpRequest);
        IdsIpsService.IdsResult result = idsIpsService.inspectRequest(httpRequest, clientIp, body);
        if (result.blocked) {
            log.warn("IDS/IPS blocked {} {} from IP {}: {} ({})",
                    httpRequest.getMethod(), httpRequest.getRequestURI(), clientIp,
                    result.reason, result.rule);
            httpResponse.setStatus(result.status);
            httpResponse.setContentType("application/json;charset=UTF-8");
            httpResponse.getWriter().write(String.format(
                    "{\"success\":false,\"message\":\"%s\",\"rule\":\"%s\",\"engine\":\"ids_ips\"}",
                    result.reason.replace("\"", "\\\""), result.rule));
            return;
        }

        chain.doFilter(actualRequest, response);
    }

    private static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String cfIp = request.getHeader("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isBlank()) return cfIp.trim();
        return request.getRemoteAddr();
    }
}

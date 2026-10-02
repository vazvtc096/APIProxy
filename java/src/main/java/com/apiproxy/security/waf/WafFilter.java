package com.apiproxy.security.waf;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * WAF Servlet Filter。
 *
 * 对应 Python __main__.py 中 before_request 编排的 WAF 检查：
 * - 全局每 IP 请求频率检查
 * - WAF 规则检查（含请求体）
 * - 命中规则返回 403/429/413
 *
 * 请求体通过 CachedBodyHttpServletRequest 包装，确保后续 Controller 仍可读取。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class WafFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(WafFilter.class);

    private final WafService wafService;

    public WafFilter(WafService wafService) {
        this.wafService = wafService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest httpRequest) ||
            !(response instanceof HttpServletResponse httpResponse)) {
            chain.doFilter(request, response);
            return;
        }

        if (!wafService.isWafEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        String clientIp = getClientIp(httpRequest);

        // 1. 全局频率限制
        WafService.WafResult rateResult = wafService.checkGlobalRateLimit(clientIp);
        if (rateResult.blocked) {
            writeBlockedResponse(httpResponse, rateResult);
            return;
        }

        // 2. 读取请求体（如需检查）
        String body = null;
        HttpServletRequest wrappedRequest = httpRequest;
        String method = httpRequest.getMethod().toUpperCase();
        String path = httpRequest.getRequestURI();
        boolean needsBodyCheck = (method.equals("POST") || method.equals("PUT") ||
                method.equals("PATCH") || method.equals("DELETE"))
                && !wafService.isBodyExempt(path);

        if (needsBodyCheck) {
            CachedBodyHttpServletRequest cached = new CachedBodyHttpServletRequest(httpRequest);
            wrappedRequest = cached;
            byte[] bodyBytes = cached.getCachedBody();
            if (bodyBytes != null && bodyBytes.length > 0) {
                if (bodyBytes.length > wafService.getMaxBodyBytes()) {
                    body = "__OVERSIZED__";
                } else {
                    body = new String(bodyBytes, StandardCharsets.UTF_8);
                }
            }
        }

        // 3. WAF 规则检查
        WafService.WafResult result = wafService.inspectRequest(wrappedRequest, clientIp, body);
        if (result.blocked) {
            log.warn("WAF blocked {} {} from IP {}: {} ({})",
                    method, path, clientIp, result.reason, result.ruleName);
            writeBlockedResponse(httpResponse, result);
            return;
        }

        chain.doFilter(wrappedRequest, response);
    }

    private void writeBlockedResponse(HttpServletResponse response, WafService.WafResult result)
            throws IOException {
        response.setStatus(result.status);
        response.setContentType("application/json;charset=UTF-8");
        String json = String.format(
                "{\"success\":false,\"message\":\"%s\",\"rule\":\"%s\"}",
                escapeJson(result.reason), result.ruleName);
        response.getWriter().write(json);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String cfIp = request.getHeader("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isBlank()) return cfIp.trim();
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp.trim();
        return request.getRemoteAddr();
    }

    /**
     * 缓存请求体的 HttpServletRequest 包装器，
     * 确保 WAF 读取后 Controller 仍能通过 getInputStream()/getReader() 读取。
     */
    public static class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {
        private final byte[] cachedBody;

        public CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
            super(request);
            InputStream is = request.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int read;
            while ((read = is.read(buf)) != -1) {
                baos.write(buf, 0, read);
            }
            this.cachedBody = baos.toByteArray();
        }

        public byte[] getCachedBody() { return cachedBody; }

        @Override
        public ServletInputStream getInputStream() {
            return new CachedBodyServletInputStream(cachedBody);
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(
                    new ByteArrayInputStream(cachedBody), StandardCharsets.UTF_8));
        }
    }

    static class CachedBodyServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream bais;

        public CachedBodyServletInputStream(byte[] body) {
            this.bais = new ByteArrayInputStream(body);
        }

        @Override
        public boolean isFinished() { return bais.available() == 0; }

        @Override
        public boolean isReady() { return true; }

        @Override
        public void setReadListener(ReadListener readListener) {
            throw new UnsupportedOperationException();
        }

        @Override
        public int read() { return bais.read(); }
    }
}

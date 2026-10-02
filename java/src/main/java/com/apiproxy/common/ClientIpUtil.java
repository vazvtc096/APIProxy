package com.apiproxy.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * 客户端 IP 提取工具。
 *
 * 对应 Python cloudflare.get_client_ip 的逻辑：
 * 依次检查 X-Forwarded-For / X-Real-IP / CF-Connecting-IP，
 * 回退到 request.getRemoteAddr()。
 */
@Component
public class ClientIpUtil {

    private static final String UNKNOWN = "unknown";

    /**
     * 从请求头中提取真实客户端 IP。
     * 优先级：X-Forwarded-For 首段 > X-Real-IP > CF-Connecting-IP > remoteAddr。
     */
    public String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return "";
        }

        // X-Forwarded-For: client, proxy1, proxy2 — 取第一个非 unknown 的
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isEmpty() && !UNKNOWN.equalsIgnoreCase(xff)) {
            for (String part : xff.split(",")) {
                String ip = part.trim();
                if (!ip.isEmpty() && !UNKNOWN.equalsIgnoreCase(ip)) {
                    return ip;
                }
            }
        }

        // X-Real-IP
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !UNKNOWN.equalsIgnoreCase(xRealIp)) {
            return xRealIp.trim();
        }

        // Cloudflare CF-Connecting-IP
        String cfIp = request.getHeader("CF-Connecting-IP");
        if (cfIp != null && !cfIp.isEmpty() && !UNKNOWN.equalsIgnoreCase(cfIp)) {
            return cfIp.trim();
        }

        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "";
    }
}

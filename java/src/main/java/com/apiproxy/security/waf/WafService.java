package com.apiproxy.security.waf;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * WAF（Web 应用防火墙）规则引擎。
 *
 * 对应 Python waf.py：
 * - SQL 注入 / XSS / 路径遍历 / 扫描器路径 / 恶意 UA 检测
 * - Host 头校验 / 请求体大小限制
 * - 全局每 IP 请求频率限制
 * - WAF 违规计数与自动封禁
 * - 请求体免检路径（自由文本端点）
 */
@Service
public class WafService {

    private static final Logger log = LoggerFactory.getLogger(WafService.class);

    @Value("${apiproxy.waf.enabled:true}")
    private boolean wafEnabled;

    @Value("${apiproxy.waf.disable-if-cloudflare:true}")
    private boolean disableIfCloudflare;

    @Value("${apiproxy.waf.max-body-bytes:1048576}")
    private int maxBodyBytes;

    @Value("${apiproxy.waf.global-rpm:600}")
    private int globalRpm;

    @Value("${apiproxy.waf.violations-rpm:10}")
    private int violationsRpm;

    @Value("${apiproxy.waf.ban-minutes:30}")
    private int banMinutes;

    private final Set<String> allowedHosts = ConcurrentHashMap.newKeySet();

    // 请求体免检路径前缀（自由文本/流式/管理类）
    private static final List<String> BODY_EXEMPT_PREFIXES = List.of(
            "/api/chat", "/v1/chat", "/v1/responses", "/v1/models",
            "/api/models", "/api/posts", "/api/transfer", "/api/friend",
            "/api/social", "/api/recharge", "/api/admin/", "/api/rcon"
    );

    // ---------- 规则正则 ----------
    private static final Pattern SQLI = Pattern.compile(
            "(?:/\\*.*?\\*/)" +
            "|\\s--\\s|\\s#\\s" +
            "|\\b(?:union|select|insert|update|delete|drop|truncate|alter|exec|execute|sleep|benchmark)\\b[\\s\\S]{0,40}?\\b(?:from|into|table|database|where|values|set|schema)\\b" +
            "|\\b(?:or|and)\\b\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+" +
            "|;\\s*(?:drop|delete|update|insert|truncate|alter)\\b" +
            "|\\bxp_cmdshell\\b|\\binformation_schema\\b" +
            "|\\bcast\\s*\\([\\s\\S]{0,30}?as\\s+(?:char|int|binary|nchar)\\b" +
            "|\\bload_file\\s*\\(|\\binto\\s+outfile\\b" +
            "|\\bpg_sleep\\b|\\bwaitfor\\s+delay\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern XSS = Pattern.compile(
            "(?:<script\\b)|(?:</script\\b)|(?:<iframe\\b)|(?:<svg\\b[^>]*\\bon)" +
            "|\\bjavascript\\s*:|\\bon(?:error|load|mouseover|focus|click)\\s*=" +
            "|(?:<img\\b[^>]*\\bsrc\\s*=\\s*['\"]?\\s*javascript)|\\bdocument\\.cookie\\b" +
            "|\\beval\\s*\\([\\s\\S]{0,20}?\\)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern TRAVERSAL = Pattern.compile(
            "(?:\\.\\./)|(?:\\.\\.\\\\)|(?:\\.\\.%2f)|(?:\\.\\.%5c)" +
            "|(?:%2e%2e)|(?:%252e%252e)|(?:/\\.\\./)|(?:\\.\\.%2f)" +
            "|(?:/etc/passwd)|(?:\\\\windows\\\\system32)|(?:%00)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SCANNER = Pattern.compile(
            "(?:/\\.env\\b)|(?:/\\.git/)|(?:/\\.aws/)|(?:/\\.ssh/)|(?:\\.env\\.txt)" +
            "|(?:/wp-admin/)|(?:/wp-login)|(?:/phpmyadmin/)|(?:/adminer)|(?:/web\\.config)" +
            "|(?:/actuator)|(?:/api/swagger)|(?:/v2/api-docs)|(?:/swagger-ui)" +
            "|(?:/boaform/)|(?:/manager/html)|(?:/cgi-bin/)|(?:/config\\.php)" +
            "|(?:\\.well-known/acme-challenge[^\\s]*\\.\\.)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern BAD_UA = Pattern.compile(
            "(?:\\bnmap\\b)|(?:\\bmasscan\\b)|(?:\\bsqlmap\\b)|(?:\\bnikto\\b)|(?:\\bwpscan\\b)" +
            "|(?:\\bacunetix\\b)|(?:\\bnetsparker\\b)|(?:\\bowasp\\s*zap\\b)|(?:\\bdirbuster\\b)" +
            "|(?:\\bgobuster\\b)|(?:\\bwfuzz\\b)|(?:\\bhydra\\b)|(?:\\bnessus\\b)|(?:\\bwhatweb\\b)" +
            "|(?:\\bzgrab\\b)|(?:\\bfimap\\b)|(?:\\bscan\\b.*\\bbot\\b)",
            Pattern.CASE_INSENSITIVE);

    // 进程内计数
    private final Map<String, List<Long>> ipRequestTimestamps = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> ipViolationTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Long> bannedIps = new ConcurrentHashMap<>(); // ip -> banExpiryEpoch
    private volatile long lastCleanup = 0;
    private static final long CLEANUP_INTERVAL = 60_000;

    // ---------- 配置 ----------

    public void setAllowedHosts(Collection<String> hosts) {
        allowedHosts.clear();
        hosts.forEach(h -> allowedHosts.add(h.toLowerCase()));
    }

    public boolean isWafEnabled() { return wafEnabled; }
    public void setWafEnabled(boolean enabled) { this.wafEnabled = enabled; }

    // ---------- 核心检查 ----------

    public static class WafResult {
        public final boolean blocked;
        public final String reason;
        public final int status;
        public final String ruleName;
        public WafResult(boolean blocked, String reason, int status, String ruleName) {
            this.blocked = blocked;
            this.reason = reason;
            this.status = status;
            this.ruleName = ruleName;
        }
        public static WafResult pass() { return new WafResult(false, "", 200, ""); }
    }

    /**
     * 对请求做 WAF 规则检查（不含请求体，请求体由 Filter 缓存后传入）。
     */
    public WafResult inspectRequest(HttpServletRequest request, String clientIp, String body) {
        if (!wafEnabled) return WafResult.pass();

        // 检查是否已被封禁
        Long expiry = bannedIps.get(clientIp);
        if (expiry != null) {
            if (System.currentTimeMillis() < expiry) {
                return new WafResult(true, "IP is temporarily banned", 403, "ip_ban");
            } else {
                bannedIps.remove(clientIp);
            }
        }

        // Cloudflare 检测
        if (disableIfCloudflare && request.getHeader("CF-Connecting-IP") != null) {
            return WafResult.pass(); // CF 已提供 WAF
        }

        // 1. Host 头校验
        if (!allowedHosts.isEmpty()) {
            String host = request.getHeader("Host");
            if (host != null) {
                String hostNoPort = host.split(":")[0].toLowerCase();
                if (!hostNoPort.isEmpty() && !allowedHosts.contains(hostNoPort)) {
                    recordViolation(clientIp);
                    return new WafResult(true, "Invalid Host header: " + hostNoPort, 403, "bad_host");
                }
            }
        }

        // 2. 收集待检查字符串
        List<String> targets = collectRequestStrings(request);
        if (body != null && !body.isBlank()) {
            targets.add(decode(body));
        }

        // 3. 规则检查
        for (String s : targets) {
            if ("__OVERSIZED__".equals(s)) {
                recordViolation(clientIp);
                return new WafResult(true, "Request body too large", 413, "oversized");
            }
            if (SQLI.matcher(s).find()) {
                recordViolation(clientIp);
                return new WafResult(true, "SQL injection detected", 403, "sqli");
            }
            if (XSS.matcher(s).find()) {
                recordViolation(clientIp);
                return new WafResult(true, "XSS / script injection detected", 403, "xss");
            }
            if (TRAVERSAL.matcher(s).find()) {
                recordViolation(clientIp);
                return new WafResult(true, "Path traversal detected", 403, "traversal");
            }
            if (SCANNER.matcher(s).find()) {
                recordViolation(clientIp);
                return new WafResult(true, "Malicious scanner path detected", 403, "scanner");
            }
        }

        // 4. 恶意 UA
        String ua = request.getHeader("User-Agent");
        if (ua != null && BAD_UA.matcher(ua).find()) {
            recordViolation(clientIp);
            return new WafResult(true, "Known scanner / malicious user-agent detected", 403, "bad_ua");
        }

        return WafResult.pass();
    }

    /**
     * 全局每 IP 请求频率检查。
     */
    public WafResult checkGlobalRateLimit(String clientIp) {
        maybeCleanup();
        long now = System.currentTimeMillis();
        List<Long> timestamps = ipRequestTimestamps.computeIfAbsent(clientIp, k -> new ArrayList<>());
        synchronized (timestamps) {
            timestamps.add(now);
            long cutoff = now - 60_000;
            timestamps.removeIf(t -> t < cutoff);
            if (timestamps.size() > globalRpm) {
                return new WafResult(true,
                        "Global rate limit exceeded (" + timestamps.size() + " req/min)", 429, "global_rpm");
            }
        }
        return WafResult.pass();
    }

    /** 判断路径是否为请求体免检 */
    public boolean isBodyExempt(String path) {
        return BODY_EXEMPT_PREFIXES.stream().anyMatch(path::startsWith);
    }

    // ---------- 内部工具 ----------

    private List<String> collectRequestStrings(HttpServletRequest request) {
        List<String> targets = new ArrayList<>();
        targets.add(decode(request.getRequestURI() != null ? request.getRequestURI() : ""));

        // query 参数
        Map<String, String[]> params = request.getParameterMap();
        if (params != null) {
            for (Map.Entry<String, String[]> entry : params.entrySet()) {
                targets.add(decode(entry.getKey()));
                for (String val : entry.getValue()) {
                    targets.add(decode(val));
                }
            }
        }

        // 关键 header
        for (String h : new String[]{"User-Agent", "Referer", "Cookie", "X-Forwarded-For", "X-Requested-With"}) {
            String val = request.getHeader(h);
            if (val != null) targets.add(decode(val));
        }
        return targets;
    }

    private void recordViolation(String clientIp) {
        maybeCleanup();
        long now = System.currentTimeMillis();
        List<Long> timestamps = ipViolationTimestamps.computeIfAbsent(clientIp, k -> new ArrayList<>());
        synchronized (timestamps) {
            timestamps.add(now);
            long cutoff = now - 60_000;
            timestamps.removeIf(t -> t < cutoff);
            if (timestamps.size() >= violationsRpm) {
                long expiry = now + (long) banMinutes * 60_000;
                bannedIps.put(clientIp, expiry);
                log.warn("Auto-banned IP {} for {} min ({} violations)", clientIp, banMinutes, timestamps.size());
            }
        }
    }

    private void maybeCleanup() {
        long now = System.currentTimeMillis();
        if (now - lastCleanup <= CLEANUP_INTERVAL) return;
        lastCleanup = now;
        long cutoff = now - 120_000;
        for (Map<String, List<Long>> store : List.of(ipRequestTimestamps, ipViolationTimestamps)) {
            for (Iterator<Map.Entry<String, List<Long>>> it = store.entrySet().iterator(); it.hasNext(); ) {
                Map.Entry<String, List<Long>> entry = it.next();
                synchronized (entry.getValue()) {
                    entry.getValue().removeIf(t -> t < cutoff);
                    if (entry.getValue().isEmpty()) it.remove();
                }
            }
        }
        // 清理过期封禁
        bannedIps.entrySet().removeIf(e -> e.getValue() < now);
    }

    private static String decode(String s) {
        if (s == null) return "";
        try {
            String prev = null;
            String cur = s;
            for (int i = 0; i < 3; i++) {
                if (cur.equals(prev)) break;
                prev = cur;
                cur = URLDecoder.decode(cur, StandardCharsets.UTF_8);
            }
            return cur;
        } catch (Exception e) {
            return s;
        }
    }

    // ---------- 状态查询 ----------

    public Map<String, Object> getStatus() {
        return Map.of(
                "enabled", wafEnabled,
                "global_rpm", globalRpm,
                "violations_rpm", violationsRpm,
                "ban_minutes", banMinutes,
                "max_body_bytes", maxBodyBytes,
                "tracked_ips", ipRequestTimestamps.size(),
                "banned_ips", bannedIps.size(),
                "allowed_hosts", allowedHosts
        );
    }

    public int getMaxBodyBytes() { return maxBodyBytes; }
}

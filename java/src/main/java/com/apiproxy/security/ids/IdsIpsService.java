package com.apiproxy.security.ids;

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
 * IDS/IPS（入侵检测与防御系统）。
 *
 * 对应 Python ids_ips.py：
 * - 签名型：Log4j/JNDI、RCE 命令注入、SSTI 模板注入、SSRF、NoSQL 注入、XXE、
 *   PHP 包装器、WebShell 名称、HTTP 请求走私、异常 HTTP 动词、参数洪水
 * - 行为型：端口/端点枚举扫描（短时间大量 404）、认证暴破（登录端点大量 401/403）
 * - 双模式：detect（IDS，仅记录）/ block（IPS，拦截）
 */
@Service
public class IdsIpsService {

    private static final Logger log = LoggerFactory.getLogger(IdsIpsService.class);

    @Value("${apiproxy.ids-ips.enabled:true}")
    private boolean enabled;

    @Value("${apiproxy.ids-ips.mode:block}")
    private String mode; // detect / block

    @Value("${apiproxy.ids-ips.enum-threshold:20}")
    private int enumThreshold; // 1分钟内 404 阈值

    @Value("${apiproxy.ids-ips.brute-force-threshold:10}")
    private int bruteForceThreshold; // 1分钟内登录失败阈值

    // ---------- 签名正则 ----------
    private static final Pattern LOG4J_JNDI = Pattern.compile(
            "\\$\\{jndi:(?:ldap|rmi|dns|ldaps|iiop|nis|nds|http)://",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern RCE_CMD_INJECTION = Pattern.compile(
            "(?:;|\\||`|\\$\\()\\s*(?:cat|ls|id|whoami|uname|pwd|curl|wget|nc|netcat|bash|sh|python|perl|ruby|php|powershell|cmd|cscript|wscript|mshta|regsvr32|rundll32)\\b" +
            "|\\b(?:bash|sh|zsh|ksh)\\s+-c\\s+['\"]" +
            "|\\b(?:system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\\s*\\(",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SSTI = Pattern.compile(
            "\\{\\{\\s*[\\d\\w]+\\s*[+\\-*/]\\s*[\\d\\w]+\\s*\\}\\}" +  // {{7*7}}
            "|\\{%\\s*.*?\\s*%\\}" +  // Jinja2 tags
            "|\\$\\{.*?\\}" +  // EL expression
            "|<%=?.*?%>",  // JSP
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SSRF = Pattern.compile(
            "(?:url|target|dest|destination|next|redirect|uri|path|continue|window|data|reference|site|html|page|feed|host|port|to|out|view|dir|show|navigation|open|file|read|load|proxy|callback|json|input|api|rpc|endpoint|action|webhook|agent|uri|path|continue|window|data|reference|site|html|page|feed|host|port|to|out|view|dir|show|navigation|open|file|read|load|proxy|callback|json|input|api|rpc|endpoint|action|webhook|agent)\\s*[=:]\\s*" +
            "(?:https?|ftp|gopher|dict|file|ldap)://" +
            "|\\b(?:169\\.254\\.169\\.254|127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|::1)\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern NOSQL_INJECTION = Pattern.compile(
            "\\{\\s*\\$ne\\s*:\\s*" +
            "|\\{\\s*\\$gt\\s*:\\s*" +
            "|\\{\\s*\\$lt\\s*:\\s*" +
            "|\\{\\s*\\$regex\\s*:\\s*" +
            "|\\{\\s*\\$where\\s*:\\s*" +
            "|\\{\\s*\\$exists\\s*:\\s*" +
            "|\\b\\$ne\\b|\\b\\$gt\\b|\\b\\$lt\\b|\\b\\$regex\\b|\\b\\$where\\b|\\b\\$exists\\b",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern XXE = Pattern.compile(
            "<!ENTITY\\s+\\w+\\s+SYSTEM" +
            "|<!DOCTYPE\\s+\\w+\\s+\\[" +
            "|xxe|<!ENTITY.*?http" +
            "|file:///etc/passwd",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PHP_WRAPPER = Pattern.compile(
            "php://(?:filter|input|stdin|stdout|stderr|fd|memory|temp|expect|glob|data|zip|phar)" +
            "|expect://" +
            "|compress\\.(?:zlib|bzip2)://",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern WEBSHELL = Pattern.compile(
            "\\b(?:c99\\.php|r57\\.php|c100\\.php|wso\\.php|b374k\\.php|antichat\\.php|shell\\.php|cmd\\.php|backdoor\\.php|webshell|eval\\(\\$_(?:GET|POST|REQUEST|COOKIE))" +
            "|assert\\(\\$_(?:GET|POST|REQUEST)" +
            "|base64_decode\\(\\$_(?:GET|POST|REQUEST)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern HTTP_SMUGGLING = Pattern.compile(
            "Transfer-Encoding:\\s*chunked.*?Content-Length:" +
            "|Content-Length:.*?Transfer-Encoding:\\s*chunked" +
            "|Transfer-Encoding:\\s*(?:identity|chunked,\\s*chunked)",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    private static final Set<String> VALID_METHODS = Set.of(
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT");

    // 行为型计数
    private final Map<String, List<Long>> ip404Timestamps = new ConcurrentHashMap<>();
    private final Map<String, List<Long>> ipAuthFailTimestamps = new ConcurrentHashMap<>();
    private final Map<String, Long> blockedIps = new ConcurrentHashMap<>();
    private volatile long lastCleanup = 0;

    private static final List<String> AUTH_PATHS = List.of(
            "/login", "/register", "/api/password-reset", "/oauth/token",
            "/api/auth", "/api/login", "/api/register"
    );

    public static class IdsResult {
        public final boolean blocked;
        public final String rule;
        public final String reason;
        public final int status;
        public final boolean isBlockMode;
        public IdsResult(boolean blocked, String rule, String reason, int status, boolean isBlockMode) {
            this.blocked = blocked;
            this.rule = rule;
            this.reason = reason;
            this.status = status;
            this.isBlockMode = isBlockMode;
        }
        public static IdsResult pass() { return new IdsResult(false, "", "", 200, false); }
    }

    /**
     * 签名型检测：检查请求是否匹配已知攻击签名。
     */
    public IdsResult inspectRequest(HttpServletRequest request, String clientIp, String body) {
        if (!enabled) return IdsResult.pass();

        // 本地回环地址白名单：开发/反代场景下 localhost 不应被 IDS/IPS 封禁
        if (isLoopback(clientIp)) return IdsResult.pass();

        // 检查已封禁
        Long expiry = blockedIps.get(clientIp);
        if (expiry != null) {
            if (System.currentTimeMillis() < expiry) {
                return new IdsResult(true, "ip_ban", "IP blocked by IDS/IPS", 403, "block".equalsIgnoreCase(mode));
            }
            blockedIps.remove(clientIp);
        }

        // 异常 HTTP 动词
        String method = request.getMethod().toUpperCase();
        if (!VALID_METHODS.contains(method)) {
            return trigger(clientIp, "invalid_method", "Invalid HTTP method: " + method, 400);
        }

        // 收集待检查字符串
        List<String> targets = collectTargets(request, body);

        // 签名检查
        for (String s : targets) {
            if (LOG4J_JNDI.matcher(s).find())
                return trigger(clientIp, "log4j_jndi", "Log4j/JNDI injection attempt detected", 403);
            if (RCE_CMD_INJECTION.matcher(s).find())
                return trigger(clientIp, "rce_cmd_injection", "RCE/command injection attempt detected", 403);
            if (SSTI.matcher(s).find())
                return trigger(clientIp, "ssti", "Server-side template injection attempt detected", 403);
            if (SSRF.matcher(s).find())
                return trigger(clientIp, "ssrf", "SSRF attempt detected", 403);
            if (NOSQL_INJECTION.matcher(s).find())
                return trigger(clientIp, "nosql_injection", "NoSQL injection attempt detected", 403);
            if (XXE.matcher(s).find())
                return trigger(clientIp, "xxe", "XXE attack detected", 403);
            if (PHP_WRAPPER.matcher(s).find())
                return trigger(clientIp, "php_wrapper", "PHP wrapper attack detected", 403);
            if (WEBSHELL.matcher(s).find())
                return trigger(clientIp, "webshell", "WebShell signature detected", 403);
        }

        // HTTP 请求走私（检查 header 组合）
        String te = request.getHeader("Transfer-Encoding");
        String cl = request.getHeader("Content-Length");
        if (te != null && cl != null && HTTP_SMUGGLING.matcher("Transfer-Encoding: " + te + " Content-Length: " + cl).find()) {
            return trigger(clientIp, "http_smuggling", "HTTP request smuggling attempt detected", 400);
        }

        return IdsResult.pass();
    }

    /**
     * 行为型：记录 404 响应，检测端点枚举扫描。
     */
    public void record404(String clientIp) {
        maybeCleanup();
        long now = System.currentTimeMillis();
        List<Long> ts = ip404Timestamps.computeIfAbsent(clientIp, k -> new ArrayList<>());
        synchronized (ts) {
            ts.add(now);
            ts.removeIf(t -> t < now - 60_000);
            if (ts.size() >= enumThreshold) {
                log.warn("IDS: endpoint enumeration detected from IP {} ({} 404s/min)", clientIp, ts.size());
                if ("block".equalsIgnoreCase(mode)) {
                    blockedIps.put(clientIp, now + 30 * 60_000);
                }
            }
        }
    }

    /**
     * 行为型：记录认证失败，检测暴破。
     */
    public void recordAuthFailure(String clientIp, String path) {
        if (AUTH_PATHS.stream().noneMatch(path::startsWith)) return;
        maybeCleanup();
        long now = System.currentTimeMillis();
        List<Long> ts = ipAuthFailTimestamps.computeIfAbsent(clientIp, k -> new ArrayList<>());
        synchronized (ts) {
            ts.add(now);
            ts.removeIf(t -> t < now - 60_000);
            if (ts.size() >= bruteForceThreshold) {
                log.warn("IDS: brute-force attack detected from IP {} ({} auth failures/min)", clientIp, ts.size());
                if ("block".equalsIgnoreCase(mode)) {
                    blockedIps.put(clientIp, now + 30 * 60_000);
                }
            }
        }
    }

    private IdsResult trigger(String clientIp, String rule, String reason, int status) {
        log.warn("IDS/IPS: {} from IP {} - {}", rule, clientIp, reason);
        boolean block = "block".equalsIgnoreCase(mode);
        if (block) {
            blockedIps.put(clientIp, System.currentTimeMillis() + 30 * 60_000);
        }
        return new IdsResult(block, rule, reason, status, block);
    }

    private List<String> collectTargets(HttpServletRequest request, String body) {
        List<String> targets = new ArrayList<>();
        targets.add(decode(request.getRequestURI() != null ? request.getRequestURI() : ""));
        String qs = request.getQueryString();
        if (qs != null) targets.add(decode(qs));

        Map<String, String[]> params = request.getParameterMap();
        if (params != null) {
            for (Map.Entry<String, String[]> e : params.entrySet()) {
                targets.add(decode(e.getKey()));
                for (String v : e.getValue()) targets.add(decode(v));
            }
        }

        // Referer/Origin 头由浏览器自动填充，必然包含 host（如 localhost:5000），
        // 不应纳入 SSRF 本地地址检测，否则正常页面跳转全部误判为 SSRF。
        for (String h : new String[]{"User-Agent", "X-Forwarded-For", "X-Requested-With", "Accept"}) {
            String v = request.getHeader(h);
            if (v != null) targets.add(decode(v));
        }

        if (body != null && !body.isBlank()) targets.add(decode(body));
        return targets;
    }

    private void maybeCleanup() {
        long now = System.currentTimeMillis();
        if (now - lastCleanup < 60_000) return;
        lastCleanup = now;
        long cutoff = now - 120_000;
        for (Map<String, List<Long>> store : List.of(ip404Timestamps, ipAuthFailTimestamps)) {
            for (Iterator<Map.Entry<String, List<Long>>> it = store.entrySet().iterator(); it.hasNext(); ) {
                Map.Entry<String, List<Long>> e = it.next();
                synchronized (e.getValue()) {
                    e.getValue().removeIf(t -> t < cutoff);
                    if (e.getValue().isEmpty()) it.remove();
                }
            }
        }
        blockedIps.entrySet().removeIf(e -> e.getValue() < now);
    }

    private static String decode(String s) {
        if (s == null) return "";
        try {
            String prev = null, cur = s;
            for (int i = 0; i < 3; i++) {
                if (cur.equals(prev)) break;
                prev = cur;
                cur = URLDecoder.decode(cur, StandardCharsets.UTF_8);
            }
            return cur;
        } catch (Exception e) { return s; }
    }

    public Map<String, Object> getStatus() {
        return Map.of(
                "enabled", enabled,
                "mode", mode,
                "enum_threshold", enumThreshold,
                "brute_force_threshold", bruteForceThreshold,
                "tracked_404_ips", ip404Timestamps.size(),
                "tracked_auth_ips", ipAuthFailTimestamps.size(),
                "blocked_ips", blockedIps.size()
        );
    }

    /** 判断是否为本地回环地址（127.0.0.1 / ::1 / 0:0:0:0:0:0:0:1） */
    private static boolean isLoopback(String ip) {
        if (ip == null) return false;
        return "127.0.0.1".equals(ip)
                || "0:0:0:0:0:0:0:1".equals(ip)
                || "::1".equals(ip)
                || "localhost".equalsIgnoreCase(ip);
    }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public void setMode(String mode) {
        if ("detect".equalsIgnoreCase(mode) || "block".equalsIgnoreCase(mode))
            this.mode = mode.toLowerCase();
    }
}

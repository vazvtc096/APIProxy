package com.apiproxy.security.webfilter;

import com.apiproxy.entity.WebAccessLog;
import com.apiproxy.repository.WebAccessLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 上网行为管理服务（Web 行为过滤 + 全站上网行为审计）。
 *
 * 对应 Python web_filter.py：
 * - URL 分类（恶意/钓鱼/赌博/成人/代理/社交/流媒体/广告）
 * - 分类拦截（block 模式）
 * - 管理员豁免
 * - 全站行为审计（写入 web_access_log）
 * - 运行期策略调整
 */
@Service
public class WebFilterService {

    private static final Logger log = LoggerFactory.getLogger(WebFilterService.class);

    @Value("${apiproxy.web-filter.enabled:true}")
    private boolean enabled;

    @Value("${apiproxy.web-filter.mode:block}")
    private String mode; // monitor / block

    @Value("${apiproxy.web-filter.log-all:true}")
    private boolean logAll;

    @Value("${apiproxy.web-filter.bypass-admin:true}")
    private boolean bypassAdmin;

    private final Set<String> blockList = ConcurrentHashMap.newKeySet();

    private final WebAccessLogRepository webAccessLogRepository;

    // 分类关键词
    private static final Map<String, List<String>> CATEGORY_KEYWORDS = Map.of(
            "malware", List.of("malware", "virus", "trojan", "exploit", "botnet", "c2",
                    "shellcode", "payload", "webshell", "后门", "木马", "病毒"),
            "phishing", List.of("phishing", "account-verify", "verify-bank", "secure-signin",
                    "login-secure", "账户验证", "钓鱼", "冒充"),
            "gambling", List.of("casino", "bet365", "gambling", "poker", "lottery", "博彩",
                    "百家乐", "彩票", "赌博", "赌球"),
            "adult", List.of("porn", "xxx", "adult", "sex", "色情", "成人", "av"),
            "proxy", List.of("free-proxy", "anonymizer", "shadowsocks", "v2ray", "trojan-go",
                    "翻墙", "科学上网", "自由门", "vpn下载", "代理服务器"),
            "social", List.of("facebook", "twitter", "instagram", "tiktok", "weibo",
                    "douyin", "qq", "wechat", "微信", "微博", "社交"),
            "streaming", List.of("youtube", "netflix", "bilibili", "iqiyi", "youku", "爱奇艺",
                    "优酷", "视频"),
            "ads", List.of("doubleclick", "adsense", "banner-ad", "广告联盟")
    );

    private static final List<String> API_PREFIXES = List.of(
            "/api/", "/v1/", "/oauth/", "/internal/", "/cluster/",
            "/admin", "/static/", "/api/console", "/api/rcon"
    );

    public WebFilterService(WebAccessLogRepository webAccessLogRepository) {
        this.webAccessLogRepository = webAccessLogRepository;
        // 默认封禁分类
        blockList.addAll(List.of("malware", "phishing", "gambling", "adult", "proxy"));
    }

    public static class InspectResult {
        public final boolean blocked;
        public final String category;
        public final String reason;
        public final int status;
        public InspectResult(boolean blocked, String category, String reason, int status) {
            this.blocked = blocked;
            this.category = category;
            this.reason = reason;
            this.status = status;
        }
        public static InspectResult pass() { return new InspectResult(false, null, null, 200); }
    }

    /**
     * 请求期检测：分类 + 拦截判断。
     */
    public InspectResult inspectRequest(HttpServletRequest request, boolean isAdmin) {
        if (!enabled) return InspectResult.pass();
        String path = request.getRequestURI();
        if (path == null || !isBrowsingPath(path)) return InspectResult.pass();

        String text = getRequestText(request);
        String category = classify(text);
        if (category == null) return InspectResult.pass();

        // 管理员豁免拦截但照常记录
        if (isAdmin && bypassAdmin) return InspectResult.pass();

        if (blockList.contains(category) && "block".equalsIgnoreCase(mode)) {
            return new InspectResult(true, category,
                    "上网行为管理：命中封禁分类「" + category + "」", 403);
        }
        return InspectResult.pass();
    }

    /**
     * 行为审计：写入 web_access_log。
     */
    public void recordAccess(HttpServletRequest request, String clientIp,
                             String username, int status, long bytes) {
        if (!enabled || !logAll) return;
        String path = request.getRequestURI();
        if (path != null && path.startsWith("/static/")) return;

        try {
            String category = classify(getRequestText(request));
            String action = status == 403 ? "blocked" : "allowed";
            WebAccessLog logEntry = new WebAccessLog();
            logEntry.setUserName(username);
            logEntry.setClientIp(clientIp);
            logEntry.setMethod(request.getMethod());
            logEntry.setPath(path != null && path.length() > 500 ? path.substring(0, 500) : path);
            logEntry.setQuery(request.getQueryString() != null && request.getQueryString().length() > 500
                    ? request.getQueryString().substring(0, 500) : request.getQueryString());
            logEntry.setCategory(category);
            logEntry.setAction(action);
            logEntry.setStatus(status);
            logEntry.setBytes((int) bytes);
            logEntry.setCreatedAt(java.time.LocalDateTime.now());
            webAccessLogRepository.save(logEntry);
        } catch (Exception e) {
            log.error("web_filter record failed: {}", e.getMessage());
        }
    }

    /** URL 分类 */
    public String classify(String text) {
        if (text == null || text.isBlank()) return null;
        String low = text.toLowerCase();
        for (Map.Entry<String, List<String>> entry : CATEGORY_KEYWORDS.entrySet()) {
            for (String kw : entry.getValue()) {
                if (low.contains(kw.toLowerCase())) return entry.getKey();
            }
        }
        return null;
    }

    private boolean isBrowsingPath(String path) {
        return API_PREFIXES.stream().noneMatch(path::startsWith);
    }

    private String getRequestText(HttpServletRequest request) {
        String path = request.getRequestURI() != null ? request.getRequestURI() : "";
        String q = request.getQueryString() != null ? request.getQueryString() : "";
        try { q = URLDecoder.decode(q, StandardCharsets.UTF_8); } catch (Exception ignored) {}
        return (path + "?" + q).toLowerCase();
    }

    // ---------- 运行期策略调整 ----------

    public boolean addBlock(String category) {
        if (category == null || category.isBlank()) return false;
        return blockList.add(category.toLowerCase().trim());
    }

    public boolean removeBlock(String category) {
        if (category == null) return false;
        return blockList.remove(category.toLowerCase().trim());
    }

    public void setMode(String mode) {
        if ("monitor".equalsIgnoreCase(mode) || "block".equalsIgnoreCase(mode)) {
            this.mode = mode.toLowerCase();
        }
    }

    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    // ---------- 状态查询 ----------

    public Map<String, Object> getStatus() {
        return Map.of(
                "enabled", enabled,
                "mode", mode,
                "log_all", logAll,
                "bypass_admin", bypassAdmin,
                "block_list", new ArrayList<>(blockList),
                "total_categories", CATEGORY_KEYWORDS.size()
        );
    }

    public List<Map<String, Object>> getCategories() {
        return CATEGORY_KEYWORDS.entrySet().stream()
                .map(e -> Map.of(
                        "category", (Object) e.getKey(),
                        "keywords", (Object) e.getValue(),
                        "blocked", (Object) blockList.contains(e.getKey())
                ))
                .toList();
    }

    public Map<String, Object> getPolicy() {
        return Map.of("mode", mode, "block_list", new ArrayList<>(blockList));
    }
}

package com.apiproxy.service;

import com.apiproxy.entity.Upstream;
import com.apiproxy.repository.UpstreamRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 多上游管理服务：上游选择 / 模型目录刷新 / CRUD。
 *
 * 对应 Python upstreams.py 的 select_upstream / refresh_models / reload_upstreams_from_db
 * 以及管理后台对 upstreams 表的增删改。
 *
 * 业务规则（对齐 Python 版）：
 * - selectUpstream：filter 启用 + 未禁用该模型 + （已知目录则须包含该模型）+ 命中 preferUpstream，
 *   按优先级升序（数字越小优先级越高）取第一个。
 * - refreshModels：逐个拉取各上游 /models 并合并，构建 model→upstream 映射；TTL 300s 缓存。
 * - reloadFromDb：从 DB 读取上游（JPA 自动）并使模型目录缓存失效。
 *
 * 注意：本服务使用 WebClient（spring-webflux）拉取上游 /models。
 * 需在 pom.xml 添加 spring-boot-starter-webflux 依赖以支持响应式 HTTP 客户端。
 */
@Service
public class UpstreamService {

    private static final Logger log = LoggerFactory.getLogger(UpstreamService.class);

    /** 模型目录缓存 TTL（秒），对齐 Python _REFRESH_TTL = 300 */
    private static final long REFRESH_TTL_SECONDS = 300;

    /** 上游 /models 拉取超时（秒） */
    private static final long FETCH_TIMEOUT_SECONDS = 30;

    /** name → 该上游支持的模型集合（拉取成功后填充；null 表示尚未拉取 = 未知） */
    private final Map<String, Set<String>> upstreamModels = new ConcurrentHashMap<>();

    /** 合并后的全部模型 id（已排序去重） */
    private volatile List<String> allModels = Collections.emptyList();

    /** 最近一次刷新时间戳（System.currentTimeMillis()） */
    private volatile long lastRefresh = 0L;

    private final UpstreamRepository upstreamRepository;
    private final ObjectMapper objectMapper;

    public UpstreamService(UpstreamRepository upstreamRepository, ObjectMapper objectMapper) {
        this.upstreamRepository = upstreamRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * 选择服务该模型的上游。
     * 对齐 Python select_upstream。
     *
     * @param model          请求模型名
     * @param preferUpstream 指定上游名（可空）；非空时仅在该上游中挑选
     * @return 命中的 Upstream 实体或 null（无可用上游）
     */
    public Upstream selectUpstream(String model, String preferUpstream) {
        if (model == null || model.isBlank()) return null;

        List<Upstream> candidates = new ArrayList<>();
        // 已按优先级升序返回（数字越小优先级越高）
        List<Upstream> enabled = upstreamRepository.findByEnabledOrderByPriorityAsc(1);
        for (Upstream u : enabled) {
            // 指定上游：名称不匹配则跳过
            if (preferUpstream != null && !preferUpstream.isBlank()
                    && !preferUpstream.equals(u.getName())) {
                continue;
            }
            // 模型被该上游禁用则跳过
            if (parseDisabledModels(u.getDisabledModels()).contains(model)) {
                continue;
            }
            // 已知目录且该上游明确不含此模型 -> 跳过（目录缺失时退化为只看 disabled_models）
            Set<String> catalog = upstreamModels.get(u.getName());
            if (catalog != null && !catalog.contains(model)) {
                continue;
            }
            candidates.add(u);
        }

        if (candidates.isEmpty()) {
            return null;
        }
        // 已按优先级升序，取第一个；指定上游时也取第一个（已过滤）
        return candidates.get(0);
    }

    /**
     * 拉取各上游模型目录并合并。返回合并后的模型 id 列表。
     * 对齐 Python refresh_models：带 TTL 缓存，逐个拉取（带超时），失败保留历史目录。
     *
     * @param force 是否强制刷新（忽略 TTL）
     * @return 合并后的模型 id 列表
     */
    public List<String> refreshModels(boolean force) {
        long now = System.currentTimeMillis();
        if (!force && !allModels.isEmpty()
                && (now - lastRefresh) < REFRESH_TTL_SECONDS * 1000L) {
            return allModels;
        }

        List<Upstream> upstreams = upstreamRepository.findByEnabled(1);
        Map<String, Set<String>> fetched = new LinkedHashMap<>();
        Map<String, List<String>> modelToUpstreams = new LinkedHashMap<>();

        for (Upstream u : upstreams) {
            String name = u.getName();
            if (u.getApiKey() == null || u.getApiKey().isBlank()) {
                continue;
            }
            try {
                Set<String> ids = fetchUpstreamModels(u);
                fetched.put(name, ids);
                for (String mid : ids) {
                    modelToUpstreams.computeIfAbsent(mid, k -> new ArrayList<>()).add(name);
                }
                log.info("Upstream '{}' reported {} models", name, ids.size());
            } catch (Exception e) {
                // 拉取失败：标记为已尝试（保留历史目录，对齐 Python setdefault）
                fetched.put(name, upstreamModels.getOrDefault(name, null));
                log.warn("Failed to list models from upstream '{}': {}", name, e.getMessage());
            }
        }

        // 原子发布结果
        upstreamModels.clear();
        upstreamModels.putAll(fetched);
        allModels = new ArrayList<>(new TreeSet<>(modelToUpstreams.keySet()));
        lastRefresh = now;
        return allModels;
    }

    /** refreshModels 的便捷重载（force=false） */
    public List<String> refreshModels() {
        return refreshModels(false);
    }

    /**
     * 从 DB 重新加载上游配置（JPA 每次查询均从 DB 读取，此处使模型目录缓存失效）。
     * 对齐 Python reload_upstreams_from_db：以 DB 为准重建客户端与缓存。
     */
    public int reloadFromDb() {
        List<Upstream> all = upstreamRepository.findAllByOrderByPriorityAscNameAsc();
        // 使模型目录缓存失效，下次 refreshModels / getAvailableModels 触发重新拉取
        lastRefresh = 0L;
        log.info("reloadFromDb: loaded {} upstreams from DB", all.size());
        return all.size();
    }

    /**
     * 返回合并后的模型 id 列表（带 TTL 缓存，过期则刷新）。
     * 对齐 Python list_all_models。
     */
    public List<String> getAvailableModels() {
        long now = System.currentTimeMillis();
        if (allModels.isEmpty() || (now - lastRefresh) >= REFRESH_TTL_SECONDS * 1000L) {
            refreshModels(false);
        }
        return allModels;
    }

    // ---------- 上游 CRUD（管理后台） ----------

    /**
     * 新增上游。对齐 Python _normalize_upstream_payload 校验逻辑。
     *
     * @param config 上游配置（name / base_url / api_key / priority / enabled / disabled_models）
     * @return 保存后的 Upstream
     */
    @Transactional
    public Upstream addUpstream(Map<String, Object> config) {
        Upstream u = normalizeConfig(config, null);
        if (upstreamRepository.findById(u.getName()).isPresent()) {
            throw new IllegalArgumentException("Upstream name already exists: " + u.getName());
        }
        Upstream saved = upstreamRepository.save(u);
        invalidateCache();
        log.info("Upstream added: {}", u.getName());
        return saved;
    }

    /**
     * 更新上游配置。
     *
     * @param name   上游名（主键）
     * @param config 新配置
     * @return 更新后的 Upstream
     */
    @Transactional
    public Upstream updateUpstream(String name, Map<String, Object> config) {
        Upstream existing = upstreamRepository.findById(name)
                .orElseThrow(() -> new IllegalArgumentException("Upstream not found: " + name));
        Upstream u = normalizeConfig(config, existing);
        // 名称变更：删除旧记录再保存新记录
        if (!name.equals(u.getName())) {
            upstreamRepository.deleteById(name);
        }
        Upstream saved = upstreamRepository.save(u);
        invalidateCache();
        log.info("Upstream updated: {}", u.getName());
        return saved;
    }

    /**
     * 删除上游。
     *
     * @param name 上游名（主键）
     */
    @Transactional
    public void deleteUpstream(String name) {
        if (upstreamRepository.findById(name).isEmpty()) {
            throw new IllegalArgumentException("Upstream not found: " + name);
        }
        upstreamRepository.deleteById(name);
        invalidateCache();
        log.info("Upstream deleted: {}", name);
    }

    /**
     * 启用/禁用上游切换。
     *
     * @param name 上游名（主键）
     * @return 切换后的 enabled 状态（1/0）
     */
    @Transactional
    public int toggleUpstream(String name) {
        Upstream u = upstreamRepository.findById(name)
                .orElseThrow(() -> new IllegalArgumentException("Upstream not found: " + name));
        int newEnabled = (u.getEnabled() != null && u.getEnabled() == 1) ? 0 : 1;
        u.setEnabled(newEnabled);
        upstreamRepository.save(u);
        invalidateCache();
        log.info("Upstream '{}' toggled to enabled={}", name, newEnabled);
        return newEnabled;
    }

    /** 返回全部上游（管理后台列表，按优先级、名称排序） */
    public List<Upstream> listUpstreams() {
        return upstreamRepository.findAllByOrderByPriorityAscNameAsc();
    }

    // ---------- 内部辅助 ----------

    /** 使模型目录缓存失效 */
    private void invalidateCache() {
        lastRefresh = 0L;
    }

    /**
     * 拉取单个上游的模型目录（GET {baseUrl}/models）。
     * 响应格式：{"data": [{"id": "gpt-4o"}, ...], ...}
     */
    @SuppressWarnings("unchecked")
    private Set<String> fetchUpstreamModels(Upstream u) {
        WebClient client = WebClient.builder()
                .baseUrl(stripTrailingSlash(u.getBaseUrl()))
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + u.getApiKey())
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .build();

        String json = client.get()
                .uri("/models")
                .retrieve()
                .bodyToMono(String.class)
                .timeout(Duration.ofSeconds(FETCH_TIMEOUT_SECONDS))
                .block();

        Set<String> ids = new HashSet<>();
        if (json == null || json.isBlank()) return ids;

        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode data = root.get("data");
            if (data != null && data.isArray()) {
                for (JsonNode m : data) {
                    JsonNode idNode = m.get("id");
                    if (idNode != null && !idNode.asText().isBlank()) {
                        ids.add(idNode.asText());
                    }
                }
            }
        } catch (JsonProcessingException e) {
            log.warn("解析上游模型列表失败 {}: {}", u.getName(), e.getMessage());
        }
        return ids;
    }

    /**
     * 规范化上游配置（对齐 Python _normalize_upstream_payload）。
     * 校验 name / base_url / api_key 必填，priority 为整数，disabled_models 转逗号分隔字符串。
     *
     * @param config   输入配置
     * @param existing 已有实体（更新时保留主键等；新增时传 null）
     * @return 规范化后的 Upstream 实体
     */
    private Upstream normalizeConfig(Map<String, Object> config, Upstream existing) {
        Upstream u = existing != null ? existing : new Upstream();
        if (config == null) {
            throw new IllegalArgumentException("Upstream config is required");
        }

        String name = str(config.get("name")).trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("name is required");
        }
        String baseUrl = str(config.get("base_url")).trim();
        String apiKey = str(config.get("api_key")).trim();
        if (baseUrl.isEmpty() || apiKey.isEmpty()) {
            throw new IllegalArgumentException("base_url and api_key are required");
        }

        int priority;
        try {
            priority = config.get("priority") != null
                    ? Integer.parseInt(String.valueOf(config.get("priority")))
                    : 100;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("priority must be an integer");
        }

        boolean enabled = config.get("enabled") == null
                || parseBool(config.get("enabled"));

        // disabled_models：list 或逗号分隔字符串 -> 规范化为逗号分隔字符串
        Object dm = config.get("disabled_models");
        String disabledModels = normalizeDisabledModels(dm);

        u.setName(name);
        u.setBaseUrl(baseUrl);
        u.setApiKey(apiKey);
        u.setPriority(priority);
        u.setEnabled(enabled ? 1 : 0);
        u.setDisabledModels(disabledModels);
        return u;
    }

    /** 解析 disabled_models 字段为 Set<String>（用于 selectUpstream 过滤） */
    private static Set<String> parseDisabledModels(String disabledModels) {
        if (disabledModels == null || disabledModels.isBlank()) {
            return Collections.emptySet();
        }
        return new HashSet<>(Arrays.asList(disabledModels.split(",")));
    }

    /** 将 disabled_models 规范化为逗号分隔字符串（对齐 Python _normalize_upstream_payload） */
    @SuppressWarnings("unchecked")
    private static String normalizeDisabledModels(Object dm) {
        if (dm == null) return "";
        if (dm instanceof List) {
            List<Object> list = (List<Object>) dm;
            return String.join(",", list.stream()
                    .map(String::valueOf)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList());
        }
        String s = String.valueOf(dm).trim();
        if (s.isEmpty()) return "";
        return String.join(",", Arrays.stream(s.split(","))
                .map(String::trim)
                .filter(x -> !x.isEmpty())
                .toList());
    }

    private static String stripTrailingSlash(String url) {
        if (url == null) return "";
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o).trim();
    }

    private static boolean parseBool(Object o) {
        if (o == null) return true;
        if (o instanceof Boolean) return (Boolean) o;
        String s = String.valueOf(o).trim().toLowerCase();
        return s.equals("true") || s.equals("1") || s.equals("yes") || s.equals("on");
    }
}

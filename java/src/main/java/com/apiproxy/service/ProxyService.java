package com.apiproxy.service;

import com.apiproxy.entity.Upstream;
import com.apiproxy.entity.User;
import com.apiproxy.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 代理服务：转发 chat completion 请求到上游 LLM 提供商并完成计费。
 *
 * 对应 Python routes/chat_proxy.py 的 chat_completions 端点核心逻辑
 * （task_manager 队列 + _process_task / _process_stream_task）与 api_caller.py 的调用与扣费。
 *
 * 职责：
 * 1. 选择上游（UpstreamService.selectUpstream）
 * 2. 通过 WebClient 转发请求（/chat/completions）
 * 3. 流式：返回 Flux<ServerSentEvent<String>> 转发上游 SSE 分片；完成后按 usage 计费
 * 4. 非流式：同步等待上游响应，按 usage 计费并返回
 *
 * 注意：本服务使用 WebClient（spring-webflux）发起响应式 HTTP 调用。
 * 需在 pom.xml 添加 spring-boot-starter-webflux 依赖以支持响应式 HTTP 客户端与 Flux 返回类型。
 */
@Service
public class ProxyService {

    private static final Logger log = LoggerFactory.getLogger(ProxyService.class);

    /** 上游调用超时（5 分钟，对齐 Python client timeout=300） */
    private static final Duration UPSTREAM_TIMEOUT = Duration.ofMinutes(5);

    /** 流式空闲心跳间隔（秒），防止中间代理因空闲 RST 连接（对齐 Python keepalive_timeout=15） */
    private static final Duration HEARTBEAT_INTERVAL = Duration.ofSeconds(15);

    /** 估算 token 时的字符/token 比率（粗略，仅 usage 缺失时兜底） */
    private static final int CHARS_PER_TOKEN = 4;

    private final UpstreamService upstreamService;
    private final BillingService billingService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    public ProxyService(UpstreamService upstreamService,
                        BillingService billingService,
                        UserRepository userRepository,
                        ObjectMapper objectMapper) {
        this.upstreamService = upstreamService;
        this.billingService = billingService;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * 代理 chat completion 请求。
     *
     * @param body     请求体（OpenAI 格式：model / messages / stream / ...）
     * @param owner    调用者用户名（用于计费与用量记录）
     * @param stream   是否流式
     * @param endpoint 端点标识（usage_logs.endpoint，如 chat.completions / responses）
     * @return 非流式返回 Map（上游 JSON 响应）；流式返回 Flux<ServerSentEvent<String>>
     */
    public Object proxyChatCompletion(Map<String, Object> body, String owner,
                                       boolean stream, String endpoint) {
        String model = str(body.get("model"));
        if (model.isBlank()) {
            throw new IllegalArgumentException("model is required");
        }

        // 选择上游
        Upstream upstream = upstreamService.selectUpstream(model, null);
        if (upstream == null) {
            throw new IllegalStateException("No available upstream for model: " + model);
        }

        if (stream) {
            return proxyStream(body, owner, model, upstream, endpoint);
        } else {
            return proxySync(body, owner, model, upstream, endpoint);
        }
    }

    /**
     * 检查用户是否被封禁。
     * 对齐 Python _is_user_banned。
     *
     * @return null 表示未封禁；非空字符串为封禁原因
     */
    public String checkBanned(String username) {
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null) return null;
        if (user.getIsBanned() != null && user.getIsBanned() == 1) {
            return user.getBanReason() != null ? user.getBanReason() : "banned";
        }
        return null;
    }

    // ---------- 非流式 ----------

    /**
     * 非流式代理：同步转发请求，解析响应 usage，计费并返回。
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> proxySync(Map<String, Object> body, String owner,
                                            String model, Upstream upstream, String endpoint) {
        long start = System.currentTimeMillis();

        WebClient client = buildWebClient(upstream);

        String json;
        try {
            json = client.post()
                    .uri("/chat/completions")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(UPSTREAM_TIMEOUT)
                    .block();
        } catch (Exception e) {
            log.error("upstream sync call failed for {} (model={}): {}", owner, model, e.getMessage());
            throw new IllegalStateException("Upstream call failed: " + e.getMessage(), e);
        }

        Map<String, Object> response;
        try {
            response = objectMapper.readValue(json, Map.class);
        } catch (Exception e) {
            log.error("failed to parse upstream response for {}: {}", owner, e.getMessage());
            throw new IllegalStateException("Failed to parse upstream response", e);
        }

        // 解析 usage 并计费
        int[] tokens = extractUsage(response.get("usage"));
        int inputTokens = tokens[0];
        int outputTokens = tokens[1];
        // usage 缺失时按 messages 与响应内容粗略估算
        if (inputTokens == 0) inputTokens = estimateTokens(toJsonString(body));
        if (outputTokens == 0) {
            outputTokens = estimateTokens(extractResponseContent(response));
        }

        double cost = billingService.calculateCost(model, inputTokens, outputTokens, upstream.getName());
        billingService.forceDeductBalance(owner, cost);
        billingService.recordUsageLog(owner, model, inputTokens, outputTokens, cost,
                false, upstream.getName(), "success", endpoint);

        log.info("proxySync ok: owner={} model={} upstream={} in_tokens={} out_tokens={} cost={} duration={}ms",
                owner, model, upstream.getName(), inputTokens, outputTokens, cost,
                System.currentTimeMillis() - start);
        return response;
    }

    // ---------- 流式 ----------

    /**
     * 流式代理：返回 Flux<ServerSentEvent<String>> 转发上游 SSE 分片，完成后计费。
     *
     * 设计：
     * - 累计分片中的 usage 与输出内容（用于 usage 缺失时兜底计费）
     * - 合并心跳分片（SSE 注释行），防止中间代理因空闲 RST 连接
     * - 流结束（doFinally）时计费，无论成功或取消都只计一次
     */
    public Flux<ServerSentEvent<String>> proxyStream(Map<String, Object> body, String owner,
                                                       String model, Upstream upstream, String endpoint) {
        // 请求 stream_options.include_usage 以获取 usage（用于计费）
        body.putIfAbsent("stream_options", Map.of("include_usage", true));

        WebClient client = buildWebClient(upstream);

        // 累计输出内容与 usage（流式中可能跨多个分片）
        StringBuilder outputContent = new StringBuilder();
        int[] usageTokens = {0, 0, 0}; // prompt / completion / total
        AtomicReference<Boolean> billed = new AtomicReference<>(false);

        // 上游 SSE 流：累计 usage / 内容后原样转发
        Flux<ServerSentEvent<String>> upstreamFlux = client.post()
                .uri("/chat/completions")
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.TEXT_EVENT_STREAM)
                .bodyValue(body)
                .retrieve()
                .bodyToFlux(new ParameterizedTypeReference<ServerSentEvent<String>>() {})
                .timeout(UPSTREAM_TIMEOUT)
                .doOnNext(event -> {
                    String data = event.data();
                    if (data != null && !"[DONE]".equals(data.trim())) {
                        parseChunkForBilling(data, outputContent, usageTokens);
                    }
                })
                .doOnError(e -> log.error("upstream stream error for {} (model={}): {}", owner, model, e.getMessage()));

        // 心跳：每 N 秒发送 SSE 注释行，上游流完成后自动取消
        Flux<ServerSentEvent<String>> heartbeat = Flux.interval(HEARTBEAT_INTERVAL)
                .map(i -> ServerSentEvent.<String>builder().comment("ping").build())
                .takeUntilOther(upstreamFlux.then());

        // 合并上游流与心跳，流结束后追加 [DONE] 并计费
        return Flux.merge(upstreamFlux, heartbeat)
                .concatWith(Mono.just(ServerSentEvent.<String>builder().data("[DONE]").build()))
                .doFinally(signal -> {
                    // 确保只计费一次
                    if (!billed.compareAndSet(false, true)) return;
                    try {
                        int inputTokens = usageTokens[0];
                        int outputTokens = usageTokens[1];
                        if (inputTokens == 0) inputTokens = estimateTokens(toJsonString(body));
                        if (outputTokens == 0) outputTokens = estimateTokens(outputContent.toString());
                        double cost = billingService.calculateCost(model, inputTokens, outputTokens,
                                upstream.getName());
                        billingService.forceDeductBalance(owner, cost);
                        billingService.recordUsageLog(owner, model, inputTokens, outputTokens, cost,
                                true, upstream.getName(), "success", endpoint);
                        log.info("proxyStream ok: owner={} model={} upstream={} in_tokens={} out_tokens={} cost={}",
                                owner, model, upstream.getName(), inputTokens, outputTokens, cost);
                    } catch (Exception e) {
                        log.error("billing after stream failed for {}: {}", owner, e.getMessage());
                    }
                });
    }

    // ---------- 内部辅助 ----------

    /** 构建指向指定上游的 WebClient */
    private WebClient buildWebClient(Upstream upstream) {
        String baseUrl = upstream.getBaseUrl();
        if (baseUrl != null && baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return WebClient.builder()
                .baseUrl(baseUrl != null ? baseUrl : "")
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + upstream.getApiKey())
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .build();
    }

    /**
     * 从 chat completion 分片中累计输出内容与 usage。
     * 分片格式：{"choices":[{"delta":{"content":"..."}}], "usage":{"prompt_tokens":..,"completion_tokens":..}}
     */
    private void parseChunkForBilling(String data, StringBuilder outputContent, int[] usageTokens) {
        try {
            JsonNode root = objectMapper.readTree(data);
            // 累计 delta.content
            JsonNode choices = root.get("choices");
            if (choices != null && choices.isArray() && choices.size() > 0) {
                JsonNode delta = choices.get(0).get("delta");
                if (delta != null) {
                    JsonNode content = delta.get("content");
                    if (content != null && !content.isNull()) {
                        outputContent.append(content.asText());
                    }
                }
            }
            // 捕获 usage（流式末尾分片可能携带）
            JsonNode usage = root.get("usage");
            if (usage != null && !usage.isNull()) {
                int p = usage.has("prompt_tokens") ? usage.get("prompt_tokens").asInt() : usageTokens[0];
                int c = usage.has("completion_tokens") ? usage.get("completion_tokens").asInt() : usageTokens[1];
                int t = usage.has("total_tokens") ? usage.get("total_tokens").asInt() : (p + c);
                if (p > 0) usageTokens[0] = p;
                if (c > 0) usageTokens[1] = c;
                if (t > 0) usageTokens[2] = t;
            }
        } catch (Exception e) {
            // 解析失败不影响转发，仅日志
            log.debug("parseChunkForBilling: skip non-JSON chunk: {}", e.getMessage());
        }
    }

    /**
     * 从非流式响应中提取 usage。
     * @return int[3]{prompt_tokens, completion_tokens, total_tokens}
     */
    private int[] extractUsage(Object usage) {
        int[] result = {0, 0, 0};
        if (usage == null) return result;
        try {
            JsonNode node = objectMapper.valueToTree(usage);
            if (node.has("prompt_tokens")) result[0] = node.get("prompt_tokens").asInt();
            if (node.has("completion_tokens")) result[1] = node.get("completion_tokens").asInt();
            if (node.has("total_tokens")) result[2] = node.get("total_tokens").asInt();
            else result[2] = result[0] + result[1];
        } catch (Exception ignored) {
        }
        return result;
    }

    /** 从非流式响应中提取 choices[0].message.content */
    @SuppressWarnings("unchecked")
    private String extractResponseContent(Map<String, Object> response) {
        Object choicesObj = response.get("choices");
        if (choicesObj instanceof java.util.List<?> choices && !choices.isEmpty()) {
            Object first = choices.get(0);
            if (first instanceof Map<?, ?> choice) {
                Object message = choice.get("message");
                if (message instanceof Map<?, ?> msg) {
                    Object content = msg.get("content");
                    return content != null ? content.toString() : "";
                }
            }
        }
        return "";
    }

    /** 粗略估算 token 数（usage 缺失时的兜底） */
    private static int estimateTokens(String text) {
        if (text == null || text.isEmpty()) return 0;
        return Math.max(1, text.length() / CHARS_PER_TOKEN);
    }

    /** 安全地将对象序列化为 JSON 字符串 */
    private String toJsonString(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o).trim();
    }
}

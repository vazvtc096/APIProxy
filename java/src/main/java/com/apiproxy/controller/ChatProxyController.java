package com.apiproxy.controller;

import com.apiproxy.entity.User;
import com.apiproxy.service.ApiKeyService;
import com.apiproxy.service.ProxyService;
import com.apiproxy.service.RateLimitService;
import com.apiproxy.service.UpstreamService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyEmitter;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OpenAI 兼容 API 网关 Controller：chat completions / responses / models。
 *
 * 对应 Python routes/chat_proxy.py：
 * - POST /v1/chat/completions, /api/chat/completions
 * - POST /v1/responses
 * - GET  /v1/models, /api/models
 *
 * 鉴权：OpenAI 兼容端点（/v1/**, /api/chat/**, /api/models）使用 API Key 认证，
 * 不走 Spring Security session。从 Authorization: Bearer 头读取 API Key，
 * 通过 ApiKeyService.verifyApiKey 验证。
 *
 * 返回类型设计：
 * - /v1/models, /api/models 仅返回 JSON，使用 ResponseEntity<Object>
 * - /v1/chat/completions, /api/chat/completions, /v1/responses 可能流式或非流式，
 *   使用 ResponseBodyEmitter 作为声明返回类型（SseEmitter 是其子类，非流式用 JSON emitter），
 *   错误通过抛出 ProxyException + @ExceptionHandler 返回正确状态码。
 *
 * 注意：流式响应通过 SseEmitter 桥接 WebClient 的 Flux<ServerSentEvent<String>>，
 * 需 spring-boot-starter-webflux 依赖。
 */
@RestController
public class ChatProxyController {

    private static final Logger log = LoggerFactory.getLogger(ChatProxyController.class);

    /** SseEmitter 超时（5 分钟，对齐 Python client timeout=300） */
    private static final long SSE_TIMEOUT_MS = 300_000L;

    private final ApiKeyService apiKeyService;
    private final ProxyService proxyService;
    private final UpstreamService upstreamService;
    private final RateLimitService rateLimitService;
    private final ObjectMapper objectMapper;

    public ChatProxyController(ApiKeyService apiKeyService,
                                ProxyService proxyService,
                                UpstreamService upstreamService,
                                RateLimitService rateLimitService,
                                ObjectMapper objectMapper) {
        this.apiKeyService = apiKeyService;
        this.proxyService = proxyService;
        this.upstreamService = upstreamService;
        this.rateLimitService = rateLimitService;
        this.objectMapper = objectMapper;
    }

    // ==================== Chat Completions ====================

    /**
     * POST /v1/chat/completions, /api/chat/completions
     * 对齐 Python chat_completions。
     *
     * 鉴权 -> 限流 -> 封禁检查 -> 转发到上游 -> 计费。
     */
    @PostMapping(value = {"/v1/chat/completions", "/api/chat/completions"},
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_EVENT_STREAM_VALUE})
    public ResponseBodyEmitter chatCompletions(@RequestBody Map<String, Object> body,
                                                HttpServletRequest request) {
        // 1. 鉴权（API Key）
        User user = authenticate(request);
        if (user == null) {
            throw new ProxyException(HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header");
        }
        String owner = user.getUserName();

        // 2. 限流（chat 维度，按用户名）
        if (!rateLimitService.allow("chat", owner)) {
            throw new ProxyException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded, please slow down");
        }

        // 3. 封禁检查
        String banReason = proxyService.checkBanned(owner);
        if (banReason != null) {
            throw new ProxyException(HttpStatus.FORBIDDEN, "Account banned: " + banReason);
        }

        // 4. 解析请求
        if (body == null || body.isEmpty()) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, "Invalid JSON body");
        }
        String model = str(body.get("model"));
        if (model.isBlank()) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, "model is required");
        }
        boolean isStream = parseBool(body.get("stream"));

        // 5. 转发到上游
        try {
            Object result = proxyService.proxyChatCompletion(body, owner, isStream, "chat.completions");
            if (isStream) {
                @SuppressWarnings("unchecked")
                Flux<ServerSentEvent<String>> flux = (Flux<ServerSentEvent<String>>) result;
                return toSseEmitter(flux);
            } else {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = (Map<String, Object>) result;
                return jsonEmitter(map);
            }
        } catch (IllegalArgumentException e) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (IllegalStateException e) {
            log.error("chat completions error for {}: {}", owner, e.getMessage());
            throw new ProxyException(HttpStatus.SERVICE_UNAVAILABLE, e.getMessage());
        }
    }

    // ==================== Responses API ====================

    /**
     * POST /v1/responses
     * 对齐 Python responses_api：把 Responses input 转为 chat messages，复用代理逻辑，
     * 再把 chat.completions 结果/流翻译回 Responses 形状。
     */
    @PostMapping(value = "/v1/responses",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_EVENT_STREAM_VALUE})
    public ResponseBodyEmitter responsesApi(@RequestBody Map<String, Object> body,
                                              HttpServletRequest request) {
        // 1. 鉴权
        User user = authenticate(request);
        if (user == null) {
            throw new ProxyException(HttpStatus.UNAUTHORIZED, "Missing or invalid Authorization header");
        }
        String owner = user.getUserName();

        // 2. 限流
        if (!rateLimitService.allow("chat", owner)) {
            throw new ProxyException(HttpStatus.TOO_MANY_REQUESTS, "Rate limit exceeded, please slow down");
        }

        // 3. 封禁检查
        String banReason = proxyService.checkBanned(owner);
        if (banReason != null) {
            throw new ProxyException(HttpStatus.FORBIDDEN, "Account banned: " + banReason);
        }

        // 4. 解析并转换为 chat messages
        if (body == null || body.isEmpty()) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, "Invalid JSON body");
        }
        String model = str(body.get("model"));
        if (model.isBlank()) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, "model is required");
        }

        Map<String, Object> chatBody = responsesToChatBody(body);
        boolean isStream = parseBool(chatBody.get("stream"));

        // 5. 转发到上游
        try {
            Object result = proxyService.proxyChatCompletion(chatBody, owner, isStream, "responses");
            if (isStream) {
                // 流式：把 chat SSE 翻译为 Responses SSE
                @SuppressWarnings("unchecked")
                Flux<ServerSentEvent<String>> chatFlux = (Flux<ServerSentEvent<String>>) result;
                return toSseEmitter(toResponsesStream(chatFlux, model));
            } else {
                // 非流式：把 chat 响应翻译为 Responses 对象
                @SuppressWarnings("unchecked")
                Map<String, Object> chatResp = (Map<String, Object>) result;
                return jsonEmitter(chatToResponses(chatResp, model));
            }
        } catch (IllegalArgumentException e) {
            throw new ProxyException(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (IllegalStateException e) {
            log.error("responses api error for {}: {}", owner, e.getMessage());
            throw new ProxyException(HttpStatus.SERVICE_UNAVAILABLE, e.getMessage());
        }
    }

    // ==================== Models ====================

    /**
     * GET /v1/models, /api/models
     * 对齐 Python list_models：返回所有上游合并后的模型列表。
     */
    @GetMapping({"/v1/models", "/api/models"})
    public ResponseEntity<Object> listModels(HttpServletRequest request) {
        // 鉴权
        User user = authenticate(request);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "unauthorized",
                            "error_description", "需要登录会话，或有效的 API Key"));
        }

        try {
            List<String> ids = upstreamService.getAvailableModels();
            List<Map<String, Object>> data = new ArrayList<>();
            for (String id : ids) {
                data.add(Map.of("id", id));
            }
            return ResponseEntity.ok(Map.of(
                    "object", "list",
                    "data", data,
                    "count", ids.size()));
        } catch (Exception e) {
            log.error("list models failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body(Map.of("error", "upstream_models_failed",
                            "error_description", e.getMessage()));
        }
    }

    // ==================== 异常处理 ====================

    /** 代理层业务异常：携带 HTTP 状态码与 OpenAI 兼容错误信息。 */
    public static class ProxyException extends RuntimeException {
        private final HttpStatus status;

        public ProxyException(HttpStatus status, String message) {
            super(message);
            this.status = status;
        }

        public HttpStatus getStatus() {
            return status;
        }
    }

    /** 将 ProxyException 转为 OpenAI 兼容错误响应。 */
    @ExceptionHandler(ProxyException.class)
    public ResponseEntity<Object> handleProxyException(ProxyException e) {
        return ResponseEntity.status(e.getStatus()).body(Map.of("error", e.getMessage()));
    }

    // ==================== 鉴权辅助 ====================

    /**
     * 从 Authorization: Bearer 头读取并验证 API Key。
     * @return 关联用户；无效返回 null
     */
    private User authenticate(HttpServletRequest request) {
        String auth = request.getHeader("Authorization");
        if (auth == null || !auth.startsWith("Bearer ")) return null;
        String token = auth.substring(7).trim();
        if (token.isEmpty()) return null;
        return apiKeyService.verifyApiKey(token).orElse(null);
    }

    // ==================== Emitter 辅助 ====================

    /**
     * 非流式响应：用 ResponseBodyEmitter 写入 JSON 响应体。
     * send() 在 emitter 被 handler 初始化前调用时会被缓冲，初始化后回放。
     */
    private ResponseBodyEmitter jsonEmitter(Object data) {
        ResponseBodyEmitter emitter = new ResponseBodyEmitter();
        try {
            emitter.send(data, MediaType.APPLICATION_JSON);
            emitter.complete();
        } catch (IOException e) {
            emitter.completeWithError(e);
        }
        return emitter;
    }

    /**
     * 将 Flux<ServerSentEvent<String>> 桥接为 SseEmitter。
     * 订阅 Flux，逐个事件转发给 SseEmitter；计费在 Flux 的 doFinally 中完成（ProxyService 负责）。
     */
    private SseEmitter toSseEmitter(Flux<ServerSentEvent<String>> flux) {
        SseEmitter emitter = new SseEmitter(SSE_TIMEOUT_MS);
        final Disposable[] disposableRef = new Disposable[1];
        Disposable disposable = flux.subscribe(
                event -> {
                    try {
                        SseEmitter.SseEventBuilder builder = SseEmitter.event();
                        if (event.event() != null) builder.name(event.event());
                        if (event.id() != null) builder.id(event.id());
                        if (event.comment() != null) builder.comment(event.comment());
                        if (event.data() != null) builder.data(event.data());
                        emitter.send(builder);
                    } catch (IOException | IllegalStateException e) {
                        log.debug("sse send failed (client disconnected?): {}", e.getMessage());
                        if (disposableRef[0] != null) disposableRef[0].dispose();
                    }
                },
                error -> {
                    log.error("sse stream error: {}", error.getMessage());
                    emitter.completeWithError(error);
                },
                emitter::complete
        );
        disposableRef[0] = disposable;
        emitter.onCompletion(disposable::dispose);
        emitter.onTimeout(disposable::dispose);
        emitter.onError(t -> disposable.dispose());
        return emitter;
    }

    // ==================== Responses ↔ Chat 转换 ====================
    // 对齐 Python core_proxy_utils.py 的 _responses_input_to_messages / _chat_to_responses / _sse_response_event

    /**
     * 将 Responses 请求体转换为 chat completions 请求体。
     * 对齐 Python _responses_input_to_messages + 参数透传。
     */
    private Map<String, Object> responsesToChatBody(Map<String, Object> body) {
        String model = str(body.get("model"));
        List<Map<String, Object>> messages = responsesInputToMessages(body);

        Map<String, Object> chatBody = new LinkedHashMap<>();
        chatBody.put("model", model);
        chatBody.put("messages", messages);
        chatBody.put("stream", parseBool(body.get("stream")));

        // 透传兼容参数（Responses → chat 命名映射）
        Map<String, String> passthrough = Map.of(
                "temperature", "temperature",
                "top_p", "top_p",
                "max_output_tokens", "max_tokens",
                "tools", "tools",
                "tool_choice", "tool_choice",
                "n", "n",
                "stop", "stop",
                "seed", "seed",
                "presence_penalty", "presence_penalty",
                "frequency_penalty", "frequency_penalty");
        for (Map.Entry<String, String> e : passthrough.entrySet()) {
            if (body.containsKey(e.getKey())) {
                chatBody.put(e.getValue(), body.get(e.getKey()));
            }
        }
        return chatBody;
    }

    /**
     * 将 Responses input（+instructions）转换为 chat messages 列表。
     * 对齐 Python _responses_input_to_messages。
     */
    private List<Map<String, Object>> responsesInputToMessages(Map<String, Object> body) {
        List<Map<String, Object>> messages = new ArrayList<>();
        Object instructions = body.get("instructions");
        if (instructions != null && !str(instructions).isEmpty()) {
            messages.add(Map.of("role", "system", "content", str(instructions)));
        }
        Object inp = body.get("input");
        if (inp instanceof String s && !s.isEmpty()) {
            messages.add(Map.of("role", "user", "content", s));
            return messages;
        }
        if (inp instanceof List<?> items) {
            for (Object item : items) {
                if (!(item instanceof Map<?, ?> m)) continue;
                String type = str(m.get("type"));
                if ("message".equals(type)) {
                    String role = str(m.get("role"));
                    if (role.isEmpty()) role = "user";
                    String content = concatTextParts(m.get("content"));
                    messages.add(Map.of("role", role, "content", content));
                } else if ("function_call_output".equals(type)) {
                    messages.add(Map.of("role", "user", "content",
                            "[function result] " + str(m.get("output"))));
                }
            }
        }
        return messages;
    }

    /** 把 content 列表（[{type, text}] 等）拼成纯文本。对齐 Python _concat_text_parts。 */
    private static String concatTextParts(Object parts) {
        if (parts == null) return "";
        if (parts instanceof String s) return s;
        StringBuilder out = new StringBuilder();
        if (parts instanceof List<?> list) {
            for (Object p : list) {
                if (p instanceof Map<?, ?> pm) {
                    if (pm.containsKey("text")) out.append(pm.get("text"));
                    else if (pm.containsKey("input")) out.append(pm.get("input"));
                } else if (p instanceof String s) {
                    out.append(s);
                }
            }
        }
        return out.toString();
    }

    /**
     * 把 chat.completions 响应翻译为 Responses 对象。
     * 对齐 Python _chat_to_responses。
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> chatToResponses(Map<String, Object> chatResp, String model) {
        List<Map<String, Object>> choices = (List<Map<String, Object>>) chatResp.getOrDefault("choices", List.of());
        Map<String, Object> msg = choices.isEmpty() ? Map.of() : choices.get(0);
        Map<String, Object> message = (Map<String, Object>) msg.getOrDefault("message", Map.of());
        String text = str(message.get("content"));
        Map<String, Object> usage = (Map<String, Object>) chatResp.getOrDefault("usage", Map.of());

        String respId = "resp_" + generateHex(24);
        String msgId = "msg_" + generateHex(24);
        long created = System.currentTimeMillis() / 1000;

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", respId);
        result.put("object", "response");
        result.put("created_at", created);
        result.put("status", "completed");
        result.put("model", chatResp.getOrDefault("model", model));
        result.put("output", List.of(Map.of(
                "id", msgId,
                "type", "message",
                "status", "completed",
                "role", "assistant",
                "content", List.of(Map.of(
                        "type", "output_text",
                        "text", text,
                        "annotations", List.of())))));
        result.put("usage", Map.of(
                "input_tokens", toInt(usage.get("prompt_tokens")),
                "output_tokens", toInt(usage.get("completion_tokens")),
                "total_tokens", toInt(usage.get("total_tokens"))));
        result.put("incomplete_details", null);
        return result;
    }

    /**
     * 把 chat completions 流式 SSE 翻译为 Responses 流式 SSE 事件序列。
     * 对齐 Python responses_api 的 generate()：response.created → in_progress →
     * output_item.added → content_part.added → output_text.delta* →
     * output_text.done → output_item.done → response.completed。
     */
    private Flux<ServerSentEvent<String>> toResponsesStream(Flux<ServerSentEvent<String>> chatFlux, String model) {
        String respId = "resp_" + generateHex(24);
        String msgId = "msg_" + generateHex(24);
        long created = System.currentTimeMillis() / 1000;
        StringBuilder text = new StringBuilder();

        // 前置事件
        Flux<ServerSentEvent<String>> prefix = Flux.just(
                sseEvent("response.created", skeleton(respId, created, "in_progress", model)),
                sseEvent("response.in_progress", skeleton(respId, created, "in_progress", model)),
                sseEvent("response.output_item.added", Map.of(
                        "output_index", 0,
                        "item", Map.of("id", msgId, "type", "message", "status", "in_progress",
                                "role", "assistant", "content", List.of()))),
                sseEvent("response.content_part.added", Map.of(
                        "item_id", msgId, "output_index", 0, "content_index", 0,
                        "part", Map.of("type", "output_text", "text", ""))));

        // 中间事件：单次订阅 chatFlux，按事件类型分流处理（避免重复触发上游 HTTP 调用与计费）
        // - data == null：心跳/注释事件 → 原样透传，保持连接活性
        // - data == "[DONE]"：丢弃（由 suffix 的 response.completed 替代）
        // - chat chunk：提取 delta.content → 转为 response.output_text.delta
        Flux<ServerSentEvent<String>> middle = chatFlux.flatMap(event -> {
            String data = event.data();
            if (data == null) {
                return Flux.just(event);
            }
            if ("[DONE]".equals(data.trim())) {
                return Flux.empty();
            }
            String content = extractDeltaContent(data);
            if (content == null || content.isEmpty()) return Flux.empty();
            text.append(content);
            return Flux.just(sseEvent("response.output_text.delta", Map.of(
                    "item_id", msgId, "output_index", 0, "content_index", 0,
                    "delta", content)));
        });

        // 结束事件（用 defer 在 middle 完成后求值 text）
        Flux<ServerSentEvent<String>> suffix = Flux.defer(() -> {
            Map<String, Object> finalItem = Map.of(
                    "id", msgId, "type", "message", "status", "completed",
                    "role", "assistant",
                    "content", List.of(Map.of("type", "output_text", "text", text.toString(), "annotations", List.of())));
            return Flux.just(
                    sseEvent("response.output_text.done", Map.of(
                            "item_id", msgId, "output_index", 0, "content_index", 0,
                            "text", text.toString())),
                    sseEvent("response.output_item.done", Map.of("output_index", 0, "item", finalItem)),
                    sseEvent("response.completed", Map.of(
                            "response", Map.of("id", respId, "object", "response", "created_at", created,
                                    "status", "completed", "model", model, "output", List.of(finalItem),
                                    "usage", null))));
        });

        return prefix.concatWith(middle).concatWith(suffix);
    }

    /** 从 chat completion chunk JSON 中提取 choices[0].delta.content */
    private String extractDeltaContent(String json) {
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode choices = root.get("choices");
            if (choices != null && choices.isArray() && choices.size() > 0) {
                JsonNode delta = choices.get(0).get("delta");
                if (delta != null) {
                    JsonNode content = delta.get("content");
                    if (content != null && !content.isNull()) {
                        return content.asText();
                    }
                }
            }
        } catch (Exception e) {
            log.debug("extractDeltaContent: skip non-JSON chunk: {}", e.getMessage());
        }
        return null;
    }

    /** 构造 Responses 事件骨架。对齐 Python _skeleton。 */
    private static Map<String, Object> skeleton(String respId, long created, String status, String model) {
        return Map.of(
                "id", respId, "object", "response", "created_at", created,
                "status", status, "model", model, "output", List.of(), "usage", null);
    }

    /** 构造一个 SSE 事件：event:<type>\ndata:<json>\n\n。对齐 Python _sse_response_event。 */
    private ServerSentEvent<String> sseEvent(String eventType, Map<String, Object> data) {
        try {
            String json = objectMapper.writeValueAsString(data);
            return ServerSentEvent.<String>builder().event(eventType).data(json).build();
        } catch (Exception e) {
            log.error("sseEvent serialize failed: {}", e.getMessage());
            return ServerSentEvent.<String>builder().event(eventType).data("{}").build();
        }
    }

    // ==================== 通用辅助 ====================

    /** 生成指定长度的随机十六进制字符串（对齐 Python secrets.token_hex） */
    private static String generateHex(int charLength) {
        String hex = UUID.randomUUID().toString().replace("-", "");
        return hex.length() >= charLength ? hex.substring(0, charLength) : hex;
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o).trim();
    }

    private static boolean parseBool(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean b) return b;
        String s = String.valueOf(o).trim().toLowerCase();
        return s.equals("true") || s.equals("1") || s.equals("yes");
    }

    private static int toInt(Object o) {
        if (o == null) return 0;
        try {
            return Integer.parseInt(String.valueOf(o));
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}

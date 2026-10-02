package com.apiproxy.service;

import com.apiproxy.entity.HookLogs;
import com.apiproxy.entity.Hooks;
import com.apiproxy.repository.HookLogsRepository;
import com.apiproxy.repository.HooksRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Hooks DSL 事件驱动执行引擎。
 *
 * 对应 Python hooks.py（1234行）：
 * - 事件驱动：request / response / auth / billing / social / system 等事件
 * - 条件 DSL：支持字段比较、正则匹配、逻辑组合（and/or/not）
 * - 动作 DSL：block / redirect / modify_header / set_variable / notify / webhook / log
 * - 优先级排序、启用/禁用、执行计数、错误统计
 * - 执行日志写入 hook_logs
 */
@Service
public class HooksEngineService {

    private static final Logger log = LoggerFactory.getLogger(HooksEngineService.class);

    private final HooksRepository hooksRepository;
    private final HookLogsRepository hookLogsRepository;

    public HooksEngineService(HooksRepository hooksRepository,
                              HookLogsRepository hookLogsRepository) {
        this.hooksRepository = hooksRepository;
        this.hookLogsRepository = hookLogsRepository;
    }

    // ---------- 事件类型 ----------
    public static final String EVT_REQUEST = "request";
    public static final String EVT_RESPONSE = "response";
    public static final String EVT_AUTH_LOGIN = "auth.login";
    public static final String EVT_AUTH_REGISTER = "auth.register";
    public static final String EVT_BILLING_CHARGE = "billing.charge";
    public static final String EVT_BILLING_RECHARGE = "billing.recharge";
    public static final String EVT_SOCIAL_POST = "social.post";
    public static final String EVT_SOCIAL_MESSAGE = "social.message";
    public static final String EVT_SYSTEM_STARTUP = "system.startup";
    public static final String EVT_SYSTEM_ERROR = "system.error";

    /**
     * 触发事件，执行所有匹配的 Hook。
     * 返回 HookResult，包含是否被拦截、修改后的上下文等。
     */
    public HookResult triggerEvent(String event, Map<String, Object> context) {
        HookResult result = new HookResult();
        result.context = new HashMap<>(context != null ? context : Map.of());

        List<Hooks> hooks = hooksRepository.findAll();
        // 按优先级排序（数字越小优先级越高）
        hooks.sort(Comparator.comparingInt(h -> h.getPriority() != null ? h.getPriority() : 100));

        for (Hooks hook : hooks) {
            if (hook.getIsEnabled() == null || hook.getIsEnabled() != 1) continue;
            if (!matchesEvent(hook, event)) continue;

            try {
                boolean conditionMet = evaluateCondition(hook.getCondition(), result.context);
                if (!conditionMet) continue;

                log.debug("Hook {} matched event {} with condition", hook.getId(), event);
                executeActions(hook, result);

                // 更新统计
                hook.setMatchCount((hook.getMatchCount() != null ? hook.getMatchCount() : 0) + 1);
                hook.setRunCount((hook.getRunCount() != null ? hook.getRunCount() : 0) + 1);
                hooksRepository.save(hook);

                // 记录日志
                recordHookLog(hook, event, true, null);

                if (result.blocked) {
                    log.info("Hook {} blocked event {}", hook.getId(), event);
                    break; // 被拦截，停止后续 hook
                }
            } catch (Exception e) {
                log.error("Hook {} execution failed: {}", hook.getId(), e.getMessage());
                hook.setErrorCount((hook.getErrorCount() != null ? hook.getErrorCount() : 0) + 1);
                hook.setLastError(e.getMessage() != null && e.getMessage().length() > 500
                        ? e.getMessage().substring(0, 500) : e.getMessage());
                hooksRepository.save(hook);
                recordHookLog(hook, event, false, e.getMessage());
            }
        }
        return result;
    }

    private boolean matchesEvent(Hooks hook, String event) {
        String events = hook.getEvents();
        if (events == null || events.isBlank()) return false;
        // events 字段存储逗号分隔的事件名，或 JSON 数组
        for (String e : events.split("[,\\s]+")) {
            if (e.trim().equals(event) || e.trim().equals("*")) return true;
        }
        return false;
    }

    /**
     * 评估条件 DSL。
     * 支持格式：
     * - JSON: {"field": "path", "op": "eq|ne|gt|lt|regex|contains|in", "value": "..."}
     * - 逻辑组合: {"and": [...], "or": [...], "not": {...}}
     * - 简单字符串: "path eq value"
     */
    @SuppressWarnings("unchecked")
    public boolean evaluateCondition(String conditionStr, Map<String, Object> context) {
        if (conditionStr == null || conditionStr.isBlank()) return true;

        // 尝试 JSON 解析
        conditionStr = conditionStr.trim();
        if (conditionStr.startsWith("{")) {
            try {
                Map<String, Object> cond = parseSimpleJson(conditionStr);
                return evaluateJsonCondition(cond, context);
            } catch (Exception e) {
                log.warn("Failed to parse hook condition JSON: {}", e.getMessage());
            }
        }

        // 简单表达式: field op value
        return evaluateSimpleExpression(conditionStr, context);
    }

    @SuppressWarnings("unchecked")
    private boolean evaluateJsonCondition(Map<String, Object> cond, Map<String, Object> context) {
        if (cond.containsKey("and")) {
            List<Object> list = (List<Object>) cond.get("and");
            for (Object item : list) {
                if (!evaluateJsonCondition((Map<String, Object>) item, context)) return false;
            }
            return true;
        }
        if (cond.containsKey("or")) {
            List<Object> list = (List<Object>) cond.get("or");
            for (Object item : list) {
                if (evaluateJsonCondition((Map<String, Object>) item, context)) return true;
            }
            return false;
        }
        if (cond.containsKey("not")) {
            return !evaluateJsonCondition((Map<String, Object>) cond.get("not"), context);
        }

        // 原子条件
        String field = (String) cond.get("field");
        String op = (String) cond.getOrDefault("op", "eq");
        Object value = cond.get("value");
        Object actual = getNestedValue(context, field);
        return compareValues(actual, op, value);
    }

    private boolean evaluateSimpleExpression(String expr, Map<String, Object> context) {
        // 格式: field op value
        String[] parts = expr.split("\\s+", 3);
        if (parts.length < 3) return true;
        Object actual = getNestedValue(context, parts[0]);
        return compareValues(actual, parts[1], parts[2]);
    }

    private boolean compareValues(Object actual, String op, Object expected) {
        String actualStr = actual != null ? actual.toString() : "";
        String expectedStr = expected != null ? expected.toString() : "";
        return switch (op.toLowerCase()) {
            case "eq", "==" -> actualStr.equals(expectedStr);
            case "ne", "!=" -> !actualStr.equals(expectedStr);
            case "gt", ">" -> compareNumeric(actualStr, expectedStr) > 0;
            case "lt", "<" -> compareNumeric(actualStr, expectedStr) < 0;
            case "gte", ">=" -> compareNumeric(actualStr, expectedStr) >= 0;
            case "lte", "<=" -> compareNumeric(actualStr, expectedStr) <= 0;
            case "contains" -> actualStr.contains(expectedStr);
            case "startswith" -> actualStr.startsWith(expectedStr);
            case "endswith" -> actualStr.endsWith(expectedStr);
            case "regex", "match" -> Pattern.compile(expectedStr, Pattern.CASE_INSENSITIVE).matcher(actualStr).find();
            case "in" -> Arrays.asList(expectedStr.split(",")).contains(actualStr);
            case "exists" -> actual != null && !actualStr.isBlank();
            default -> actualStr.equals(expectedStr);
        };
    }

    private int compareNumeric(String a, String b) {
        try {
            return Double.compare(Double.parseDouble(a), Double.parseDouble(b));
        } catch (NumberFormatException e) {
            return a.compareTo(b);
        }
    }

    private Object getNestedValue(Map<String, Object> context, String path) {
        if (path == null) return null;
        String[] parts = path.split("\\.");
        Object current = context;
        for (String part : parts) {
            if (current instanceof Map<?, ?> map) {
                current = map.get(part);
            } else {
                return null;
            }
        }
        return current;
    }

    /**
     * 执行 Hook 动作。
     * actions 字段格式：JSON 数组或逗号分隔的动作描述
     */
    @SuppressWarnings("unchecked")
    private void executeActions(Hooks hook, HookResult result) {
        String actionsStr = hook.getActions();
        if (actionsStr == null || actionsStr.isBlank()) return;

        actionsStr = actionsStr.trim();
        List<Map<String, Object>> actions;
        if (actionsStr.startsWith("[")) {
            actions = parseJsonArray(actionsStr);
        } else {
            // 简单格式: action:param
            actions = new ArrayList<>();
            for (String a : actionsStr.split(";")) {
                String[] kv = a.trim().split(":", 2);
                Map<String, Object> action = new HashMap<>();
                action.put("type", kv[0].trim());
                if (kv.length > 1) action.put("param", kv[1].trim());
                actions.add(action);
            }
        }

        for (Map<String, Object> action : actions) {
            String type = (String) action.get("type");
            if (type == null) continue;
            executeSingleAction(type, action, result);
        }
    }

    private void executeSingleAction(String type, Map<String, Object> action, HookResult result) {
        switch (type.toLowerCase()) {
            case "block", "deny", "reject" -> {
                result.blocked = true;
                result.blockReason = (String) action.getOrDefault("reason", "Blocked by hook");
                result.blockStatus = (Integer) action.getOrDefault("status", 403);
            }
            case "redirect" -> {
                result.redirectUrl = (String) action.get("url");
                result.blocked = true;
                result.blockStatus = 302;
            }
            case "set_header", "add_header" -> {
                String name = (String) action.get("name");
                String value = (String) action.get("value");
                if (name != null) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> headers = (Map<String, String>) result.context
                            .computeIfAbsent("response_headers", k -> new HashMap<>());
                    headers.put(name, value);
                }
            }
            case "set_variable", "set_var" -> {
                String name = (String) action.get("name");
                Object value = action.get("value");
                if (name != null) result.context.put(name, value);
            }
            case "log" -> {
                String level = (String) action.getOrDefault("level", "info");
                String message = (String) action.getOrDefault("message", "Hook triggered");
                switch (level.toLowerCase()) {
                    case "warn" -> log.warn(message);
                    case "error" -> log.error(message);
                    case "debug" -> log.debug(message);
                    default -> log.info(message);
                }
            }
            case "notify" -> log.info("Hook notify action: {}", action.get("message"));
            case "webhook" -> log.info("Hook webhook action: {}", action.get("url"));
            default -> log.debug("Unknown hook action type: {}", type);
        }
    }

    @Transactional
    public void recordHookLog(Hooks hook, String event, boolean success, String error) {
        try {
            HookLogs logEntry = new HookLogs();
            logEntry.setHookId(hook.getId() != null ? hook.getId().toString() : null);
            logEntry.setHookName(hook.getName());
            logEntry.setEventName(event);
            logEntry.setMatched(success ? 1 : 0);
            logEntry.setError(error != null && error.length() > 1000 ? error.substring(0, 1000) : error);
            logEntry.setCreatedAt(LocalDateTime.now());
            hookLogsRepository.save(logEntry);
        } catch (Exception e) {
            log.error("Failed to record hook log: {}", e.getMessage());
        }
    }

    // ---------- 简单 JSON 解析（避免额外依赖） ----------

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseSimpleJson(String json) {
        // 简单 JSON 解析，支持嵌套对象和数组
        json = json.trim();
        if (!json.startsWith("{")) throw new IllegalArgumentException("Not a JSON object");
        return (Map<String, Object>) parseValue(json, new int[]{1});
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> parseJsonArray(String json) {
        json = json.trim();
        if (!json.startsWith("[")) throw new IllegalArgumentException("Not a JSON array");
        return (List<Map<String, Object>>) parseValue(json, new int[]{1});
    }

    private Object parseValue(String json, int[] pos) {
        skipWhitespace(json, pos);
        if (pos[0] >= json.length()) return null;
        char c = json.charAt(pos[0]);
        if (c == '{') return parseObject(json, pos);
        if (c == '[') return parseArray(json, pos);
        if (c == '"') return parseString(json, pos);
        if (c == 't' || c == 'f') return parseBoolean(json, pos);
        if (c == 'n') { pos[0] += 4; return null; }
        return parseNumber(json, pos);
    }

    private Map<String, Object> parseObject(String json, int[] pos) {
        Map<String, Object> obj = new HashMap<>();
        pos[0]++; // skip {
        skipWhitespace(json, pos);
        while (pos[0] < json.length() && json.charAt(pos[0]) != '}') {
            skipWhitespace(json, pos);
            String key = parseString(json, pos);
            skipWhitespace(json, pos);
            pos[0]++; // skip :
            Object value = parseValue(json, pos);
            obj.put(key, value);
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') pos[0]++;
        }
        pos[0]++; // skip }
        return obj;
    }

    private List<Object> parseArray(String json, int[] pos) {
        List<Object> arr = new ArrayList<>();
        pos[0]++; // skip [
        skipWhitespace(json, pos);
        while (pos[0] < json.length() && json.charAt(pos[0]) != ']') {
            arr.add(parseValue(json, pos));
            skipWhitespace(json, pos);
            if (pos[0] < json.length() && json.charAt(pos[0]) == ',') pos[0]++;
        }
        pos[0]++; // skip ]
        return arr;
    }

    private String parseString(String json, int[] pos) {
        StringBuilder sb = new StringBuilder();
        pos[0]++; // skip "
        while (pos[0] < json.length() && json.charAt(pos[0]) != '"') {
            if (json.charAt(pos[0]) == '\\') {
                pos[0]++;
                if (pos[0] < json.length()) {
                    char esc = json.charAt(pos[0]);
                    sb.append(switch (esc) {
                        case 'n' -> '\n';
                        case 't' -> '\t';
                        case 'r' -> '\r';
                        case '"' -> '"';
                        case '\\' -> '\\';
                        default -> esc;
                    });
                }
            } else {
                sb.append(json.charAt(pos[0]));
            }
            pos[0]++;
        }
        pos[0]++; // skip "
        return sb.toString();
    }

    private Boolean parseBoolean(String json, int[] pos) {
        if (json.startsWith("true", pos[0])) { pos[0] += 4; return true; }
        if (json.startsWith("false", pos[0])) { pos[0] += 5; return false; }
        return null;
    }

    private Number parseNumber(String json, int[] pos) {
        int start = pos[0];
        while (pos[0] < json.length() && (Character.isDigit(json.charAt(pos[0]))
                || json.charAt(pos[0]) == '-' || json.charAt(pos[0]) == '.'
                || json.charAt(pos[0]) == 'e' || json.charAt(pos[0]) == 'E')) {
            pos[0]++;
        }
        String numStr = json.substring(start, pos[0]);
        try {
            if (numStr.contains(".") || numStr.contains("e") || numStr.contains("E")) {
                return Double.parseDouble(numStr);
            }
            return Long.parseLong(numStr);
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void skipWhitespace(String json, int[] pos) {
        while (pos[0] < json.length() && Character.isWhitespace(json.charAt(pos[0]))) pos[0]++;
    }

    // ---------- Hook 管理 ----------

    public List<Hooks> listHooks() {
        return hooksRepository.findAll();
    }

    @Transactional
    public Hooks createHook(Hooks hook) {
        hook.setCreatedAt(LocalDateTime.now());
        hook.setUpdatedAt(LocalDateTime.now());
        hook.setRunCount(0);
        hook.setMatchCount(0);
        hook.setErrorCount(0);
        return hooksRepository.save(hook);
    }

    @Transactional
    public Hooks updateHook(Long id, Hooks updates) {
        Hooks hook = hooksRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Hook not found"));
        if (updates.getName() != null) hook.setName(updates.getName());
        if (updates.getDescription() != null) hook.setDescription(updates.getDescription());
        if (updates.getEvents() != null) hook.setEvents(updates.getEvents());
        if (updates.getCondition() != null) hook.setCondition(updates.getCondition());
        if (updates.getActions() != null) hook.setActions(updates.getActions());
        if (updates.getPriority() != null) hook.setPriority(updates.getPriority());
        if (updates.getIsEnabled() != null) hook.setIsEnabled(updates.getIsEnabled());
        hook.setUpdatedAt(LocalDateTime.now());
        return hooksRepository.save(hook);
    }

    @Transactional
    public void deleteHook(Long id) {
        hooksRepository.deleteById(id);
    }

    public List<HookLogs> listHookLogs(Long hookId, int limit) {
        List<HookLogs> all = hookLogsRepository.findAll();
        return all.stream()
                .filter(l -> hookId == null || hookId.equals(l.getHookId()))
                .sorted(Comparator.comparing(HookLogs::getCreatedAt).reversed())
                .limit(limit)
                .toList();
    }

    /**
     * Hook 执行结果。
     */
    public static class HookResult {
        public boolean blocked = false;
        public String blockReason = "";
        public int blockStatus = 403;
        public String redirectUrl = null;
        public Map<String, Object> context = new HashMap<>();
    }
}

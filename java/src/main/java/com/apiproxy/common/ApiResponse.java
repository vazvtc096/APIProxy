package com.apiproxy.common;

import java.util.HashMap;
import java.util.Map;

/**
 * 统一 API 响应封装。
 *
 * 对应 Python 路由中大量出现的 `return jsonify({...}), status` 模式。
 * Spring Boot 默认会序列化为 JSON，无需额外注解。
 */
public class ApiResponse {

    private boolean success;
    private String message;
    private Object data;

    public ApiResponse() {}

    public ApiResponse(boolean success, String message, Object data) {
        this.success = success;
        this.message = message;
        this.data = data;
    }

    public static ApiResponse ok(Object data) {
        return new ApiResponse(true, "ok", data);
    }

    public static ApiResponse ok() {
        return new ApiResponse(true, "ok", null);
    }

    public static ApiResponse ok(String message, Object data) {
        return new ApiResponse(true, message, data);
    }

    public static ApiResponse fail(String message) {
        return new ApiResponse(false, message, null);
    }

    public static ApiResponse fail(String message, Object data) {
        return new ApiResponse(false, message, data);
    }

    /** 快速构造键值对 data，避免显式创建 Map */
    public static Map<String, Object> kv(Object... kv) {
        if (kv.length % 2 != 0) {
            throw new IllegalArgumentException("kv 必须成对出现");
        }
        Map<String, Object> map = new HashMap<>(kv.length / 2);
        for (int i = 0; i < kv.length; i += 2) {
            map.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return map;
    }

    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public Object getData() { return data; }
    public void setSuccess(boolean success) { this.success = success; }
    public void setMessage(String message) { this.message = message; }
    public void setData(Object data) { this.data = data; }
}

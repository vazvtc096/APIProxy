package com.apiproxy.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 限流服务（内存版，对齐 Python core_rate_limit 的 _check_rate_limit）。
 *
 * Python 版按 category 定义窗口与上限：chat=60s/60、register/login=60s/10 等。
 * Java 版先用内存滑动窗口，后续可升级为 Redis 共享限流（多实例部署时）。
 *
 * 对应 Python core_rate_limit.py 的 _check_rate_limit / _get_rate_limit_retry_after。
 */
@Service
public class RateLimitService {

    /** 类别配置：category → {windowSeconds, maxRequests} */
    private static final Map<String, long[]> CATEGORIES = Map.of(
            "chat", new long[]{60, 60},
            "register", new long[]{60, 10},
            "login", new long[]{60, 10},
            "password_reset", new long[]{300, 5}
    );

    /** key = category + ":" + key（用户名或 IP），value = 滑动窗口计数 */
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    private static final class Window {
        final long windowEnd;
        final AtomicInteger count = new AtomicInteger(0);
        Window(long windowEnd) { this.windowEnd = windowEnd; }
    }

    /**
     * 检查限流。
     * @param category 限流类别（chat/register/login/password_reset）
     * @param key       维度键（用户名/IP）
     * @return true 放行，false 拒绝
     */
    public boolean allow(String category, String key) {
        return remaining(category, key) >= 0;
    }

    /**
     * 返回剩余次数（已计数后）。
     * @return 剩余次数；-1 表示该类别未配置（默认放行，返回大数）
     */
    public int remaining(String category, String key) {
        long[] cfg = CATEGORIES.get(category);
        if (cfg == null) return Integer.MAX_VALUE;
        long now = System.currentTimeMillis() / 1000;
        long windowEnd = now + (long) cfg[0];
        String mapKey = category + ":" + key;
        Window w = windows.compute(mapKey, (k, existing) -> {
            if (existing == null || existing.windowEnd <= now) {
                Window fresh = new Window(windowEnd);
                fresh.count.set(1);
                return fresh;
            }
            existing.count.incrementAndGet();
            return existing;
        });
        int max = (int) cfg[1];
        int used = w.count.get();
        return max - used;
    }

    /** 距离下次可请求的秒数（用于 Retry-After 头） */
    public long retryAfter(String category, String key) {
        long[] cfg = CATEGORIES.get(category);
        if (cfg == null) return 0;
        long now = System.currentTimeMillis() / 1000;
        Window w = windows.get(category + ":" + key);
        if (w == null) return 0;
        return Math.max(0, w.windowEnd - now);
    }
}

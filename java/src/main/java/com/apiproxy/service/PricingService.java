package com.apiproxy.service;

import com.apiproxy.entity.ModelPrice;
import com.apiproxy.entity.PricingSchedule;
import com.apiproxy.repository.ModelPriceRepository;
import com.apiproxy.repository.PricingScheduleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 定价服务：按时段解析模型单价。
 *
 * 对应 Python pricing.py 的 resolve_price / reload_pricing_from_db / _db_price。
 *
 * 解析规则（对齐 Python 版）：
 * 1) model@upstream 专属价（命中优先，含时段）
 * 2) model 通用价（含时段）
 * 3) DB model_prices 管理员定价兜底（无时段）
 * 4) 全局 default（input=2.0, output=4.0）
 *
 * 时段支持跨午夜（start > end 视为 wrap，如 22:00:00-06:00:00）。
 */
@Service
public class PricingService {

    private static final Logger log = LoggerFactory.getLogger(PricingService.class);

    /** 全局兜底单价（对齐 Python _FALLBACK / UNEXCEPT_MODEL） */
    private static final double DEFAULT_INPUT = 2.0;
    private static final double DEFAULT_OUTPUT = 4.0;

    private final ModelPriceRepository modelPriceRepository;
    private final PricingScheduleRepository pricingScheduleRepository;

    /** 内存定价表：key = "model" 或 "model@upstream" → 启用的时段列表 */
    private final Map<String, List<PricingSchedule>> pricingMap = new ConcurrentHashMap<>();

    public PricingService(ModelPriceRepository modelPriceRepository,
                          PricingScheduleRepository pricingScheduleRepository) {
        this.modelPriceRepository = modelPriceRepository;
        this.pricingScheduleRepository = pricingScheduleRepository;
    }

    /**
     * 解析模型单价。
     * @param model        模型名（必填）
     * @param upstreamName 上游名（可选，命中 model@upstream 专属价）
     * @return double[2]{inputPerMillion, outputPerMillion}
     */
    public double[] resolvePrice(String model, String upstreamName) {
        int nowSec = LocalTime.now().toSecondOfDay();

        // 1) model@upstream 专属价（命中优先）
        if (upstreamName != null && !upstreamName.isBlank()) {
            double[] r = resolveFromSchedules(model + "@" + upstreamName, nowSec);
            if (r != null) return r;
        }

        // 2) model 通用价
        double[] r = resolveFromSchedules(model, nowSec);
        if (r != null) return r;

        // 3) DB model_prices 管理员定价兜底
        ModelPrice mp = modelPriceRepository.findByModelAndPriced(model, 1).orElse(null);
        if (mp != null) {
            double in = mp.getInput() != null ? mp.getInput() : DEFAULT_INPUT;
            double out = mp.getOutput() != null ? mp.getOutput() : DEFAULT_OUTPUT;
            return new double[]{in, out};
        }

        // 4) 全局 default
        return new double[]{DEFAULT_INPUT, DEFAULT_OUTPUT};
    }

    /**
     * 从内存定价表中按当前时段解析单价。
     * @return double[2]{input, output}；无命中返回 null
     */
    private double[] resolveFromSchedules(String key, int nowSec) {
        List<PricingSchedule> schedules = pricingMap.get(key);
        if (schedules == null || schedules.isEmpty()) return null;
        for (PricingSchedule sch : schedules) {
            if (sch.getEnabled() == null || sch.getEnabled() != 1) continue;
            int start = parseHms(sch.getStart());
            int end = parseHms(sch.getEnd());
            if (inWindow(nowSec, start, end)) {
                double in = sch.getInput() != null ? sch.getInput() : DEFAULT_INPUT;
                double out = sch.getOutput() != null ? sch.getOutput() : DEFAULT_OUTPUT;
                return new double[]{in, out};
            }
        }
        return null;
    }

    /**
     * 从 DB pricing_schedules 表加载时段计费到内存表。
     * 对齐 Python reload_pricing_from_db：DB 有 schedules 的模型覆盖内存表。
     * @return 加载的时段行数；-1 表示读取失败
     */
    public int reloadFromDb() {
        try {
            List<PricingSchedule> all = pricingScheduleRepository.findAll();
            Map<String, List<PricingSchedule>> grouped = new HashMap<>();
            for (PricingSchedule sch : all) {
                if (sch.getModel() == null) continue;
                grouped.computeIfAbsent(sch.getModel(), k -> new ArrayList<>()).add(sch);
            }
            pricingMap.clear();
            pricingMap.putAll(grouped);
            log.info("reloadFromDb: loaded {} schedule rows for {} models", all.size(), grouped.size());
            return all.size();
        } catch (Exception e) {
            log.warn("reloadFromDb: failed: {}", e.getMessage());
            return -1;
        }
    }

    // ---------- 辅助 ----------

    /** 'HH:MM:SS' 或 'HH:MM' → 当日秒数；解析失败返回 -1 */
    private static int parseHms(String s) {
        if (s == null || s.isBlank()) return -1;
        String[] parts = s.trim().split(":");
        try {
            int h = Integer.parseInt(parts[0]);
            int m = Integer.parseInt(parts[1]);
            int sec = parts.length > 2 ? Integer.parseInt(parts[2]) : 0;
            return h * 3600 + m * 60 + sec;
        } catch (NumberFormatException | ArrayIndexOutOfBoundsException e) {
            return -1;
        }
    }

    /** 判断 nowSec 是否落在 [start, end]；支持跨午夜（start > end） */
    private static boolean inWindow(int nowSec, int startSec, int endSec) {
        if (startSec < 0 || endSec < 0) return false;
        if (startSec <= endSec) {
            return startSec <= nowSec && nowSec <= endSec;
        }
        // 跨午夜：22:00:00 - 06:00:00
        return nowSec >= startSec || nowSec <= endSec;
    }
}

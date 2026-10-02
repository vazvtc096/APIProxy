package com.apiproxy.service;

import com.apiproxy.entity.UsageLog;
import com.apiproxy.entity.User;
import com.apiproxy.repository.UsageLogRepository;
import com.apiproxy.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 计费与余额服务：原子扣费 / 退还 / 用量记录 / 费用计算。
 *
 * 对应 Python core_billing.py 的 _atomic_pre_deduct_balence /
 * _atomic_force_deduct_balence / _atomic_add_balence / _record_usage_log / _calculate_cost。
 *
 * 业务规则（对齐 Python 版）：
 * - 预扣费：读 balence/allow_overdraft/max_overdraft，余额不足且不允许超支则拒绝；
 *   超支超限则拒绝；通过后原子扣减 balence = balence - amount
 * - 强制扣费：输出已产生，必须扣，不做超支检查
 * - 退还：API 调用失败时回退预扣费用，原子增加 balence
 * - 费用计算：(tokens / 1_000_000) × per_million_price，input/output 分别计价后求和
 */
@Service
public class BillingService {

    private static final Logger log = LoggerFactory.getLogger(BillingService.class);

    private final UserRepository userRepository;
    private final UsageLogRepository usageLogRepository;
    private final PricingService pricingService;

    public BillingService(UserRepository userRepository,
                          UsageLogRepository usageLogRepository,
                          PricingService pricingService) {
        this.userRepository = userRepository;
        this.usageLogRepository = usageLogRepository;
        this.pricingService = pricingService;
    }

    /**
     * 事务中原子预扣费（防止并发竞态超支）。
     * 对齐 Python _atomic_pre_deduct_balence。
     *
     * @param username 用户名
     * @param amount  扣费金额（必须 > 0）
     * @return Map{success, newBalance, message}；amount <= 0 时直接成功
     */
    @Transactional
    public Map<String, Object> preDeductBalance(String username, double amount) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (amount <= 0) {
            result.put("success", true);
            result.put("newBalance", 0.0);
            result.put("message", "OK");
            return result;
        }

        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null) {
            result.put("success", false);
            result.put("newBalance", 0.0);
            result.put("message", "User not found");
            return result;
        }

        double balance = user.getBalence() != null ? user.getBalence() : 0.0;
        double maxOd = user.getMaxOverdraft() != null ? user.getMaxOverdraft() : 0.0;
        // allow_overdraft 列在实体中未映射，通过原生 SQL 读取
        Integer allowOdRaw = userRepository.findAllowOverdraftByUserName(username);
        boolean allowOd = allowOdRaw != null && allowOdRaw == 1;

        double newBalance = round6(balance - amount);
        double overdraft = Math.max(0.0, -newBalance);

        // 不允许超支且结果为负 → 拒绝
        if (!allowOd && newBalance < 0) {
            result.put("success", false);
            result.put("newBalance", balance);
            result.put("message", String.format("余额不足：需 %.6f，当前 %.6f", amount, balance));
            return result;
        }
        // 超支超过限额 → 拒绝
        if (overdraft > maxOd + 1e-9) {
            result.put("success", false);
            result.put("newBalance", balance);
            result.put("message", String.format("余额不足（超支超限）：需 %.6f，当前 %.6f，限额 %.6f",
                    amount, balance, maxOd));
            return result;
        }

        // 原子扣减
        user.setBalence(newBalance);
        userRepository.save(user);

        result.put("success", true);
        result.put("newBalance", newBalance);
        result.put("message", "OK");
        return result;
    }

    /**
     * 事务中原子强制扣费（输出已产生，必须扣，不做超支检查）。
     * 对齐 Python _atomic_force_deduct_balence。
     *
     * @param username 用户名
     * @param amount  扣费金额
     * @return 扣费后余额
     */
    @Transactional
    public double forceDeductBalance(String username, double amount) {
        if (amount <= 0) return 0.0;
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null) return 0.0;
        double balance = user.getBalence() != null ? user.getBalence() : 0.0;
        double newBalance = round6(balance - amount);
        user.setBalence(newBalance);
        userRepository.save(user);
        return newBalance;
    }

    /**
     * 事务中原子退还余额（API 调用失败时回退预扣费用）。
     * 对齐 Python _atomic_add_balence。
     *
     * @param username 用户名
     * @param amount   退还金额
     * @return 退还后余额
     */
    @Transactional
    public double addBalance(String username, double amount) {
        if (amount <= 0) return 0.0;
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null) return 0.0;
        double balance = user.getBalence() != null ? user.getBalence() : 0.0;
        double newBalance = round6(balance + amount);
        user.setBalence(newBalance);
        userRepository.save(user);
        return newBalance;
    }

    /**
     * 写入一条用量与费用明细到 usage_logs。
     * 对齐 Python _record_usage_log。
     *
     * @param owner        用户名
     * @param model        模型名
     * @param inputTokens  输入 token 数（Python 版为字符数）
     * @param outputTokens 输出 token 数
     * @param totalCost    总费用
     * @param isStream     是否流式
     * @param upstreamName 上游名
     * @param status       状态（默认 success）
     * @param endpoint     端点（默认 chat.completions）
     */
    @Transactional
    public void recordUsageLog(String owner, String model, int inputTokens, int outputTokens,
                               double totalCost, boolean isStream, String upstreamName,
                               String status, String endpoint) {
        try {
            User user = userRepository.findByUserName(owner).orElse(null);
            if (user == null) {
                log.warn("recordUsageLog: user not found: {}", owner);
                return;
            }
            UsageLog logEntry = new UsageLog();
            logEntry.setLogId("ul_" + generateUid());
            logEntry.setUserUid(user.getUid());
            logEntry.setUserName(owner);
            logEntry.setModel(model);
            logEntry.setEndpoint(endpoint != null ? endpoint : "chat.completions");
            logEntry.setInputTokens(inputTokens);
            logEntry.setOutputTokens(outputTokens);
            logEntry.setTotalTokens(inputTokens + outputTokens);
            logEntry.setCost(round6(totalCost));
            logEntry.setIsStream(isStream ? 1 : 0);
            logEntry.setStatus(status != null ? status : "success");
            logEntry.setUpstream(upstreamName != null ? upstreamName : "");
            logEntry.setCreatedAt(LocalDateTime.now());
            usageLogRepository.save(logEntry);
        } catch (Exception e) {
            log.error("record usage_log failed: {}", e.getMessage());
        }
    }

    /**
     * 计算费用：按 input/output token 数与模型单价计算。
     * 对齐 Python _calculate_cost（input/output 分别计价后求和）。
     *
     * @param model        模型名
     * @param inputTokens  输入 token 数
     * @param outputTokens 输出 token 数
     * @param upstreamName 上游名（可选，命中 model@upstream 专属价）
     * @return 总费用（四舍五入到 6 位小数）
     */
    public double calculateCost(String model, int inputTokens, int outputTokens, String upstreamName) {
        double[] prices = pricingService.resolvePrice(model, upstreamName);
        double inputPerMillion = prices[0];
        double outputPerMillion = prices[1];
        double inputCost = (inputTokens / 1_000_000.0) * inputPerMillion;
        double outputCost = (outputTokens / 1_000_000.0) * outputPerMillion;
        return round6(inputCost + outputCost);
    }

    // ---------- 辅助 ----------

    /** 6 位小数四舍五入（对齐 Python round(x, 6)） */
    private static double round6(double v) {
        return Math.round(v * 1_000_000.0) / 1_000_000.0;
    }

    /** 生成 12 位十六进制 UID（对齐 Python generate_uid: uuid4().hex[:12]） */
    private static String generateUid() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }
}

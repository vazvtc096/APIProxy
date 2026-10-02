package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.BalenceTransaction;
import com.apiproxy.entity.RechargeRequest;
import com.apiproxy.repository.BalenceTransactionRepository;
import com.apiproxy.repository.RechargeRequestRepository;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.RateLimitService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 充值与交易 Controller。
 *
 * 对应 Python routes/recharge.py 的端点：
 * - POST /api/recharge/request    用户提交充值请求
 * - GET  /api/recharge/my-requests 查看我的充值请求
 * - GET  /api/transactions         获取余额变动记录
 */
@RestController
public class BillingController {

    private static final Logger log = LoggerFactory.getLogger(BillingController.class);

    private static final double MAX_RECHARGE_AMOUNT = 10000.0;

    private final RechargeRequestRepository rechargeRepository;
    private final BalenceTransactionRepository transactionRepository;
    private final RateLimitService rateLimit;

    public BillingController(RechargeRequestRepository rechargeRepository,
                             BalenceTransactionRepository transactionRepository,
                             RateLimitService rateLimit) {
        this.rechargeRepository = rechargeRepository;
        this.transactionRepository = transactionRepository;
        this.rateLimit = rateLimit;
    }

    /**
     * 用户提交充值请求。
     * 对齐 Python /api/recharge/request：限流 → 鉴权 → 校验金额 → 插入 pending 请求。
     */
    @PostMapping("/api/recharge/request")
    @Transactional
    public ResponseEntity<ApiResponse> rechargeRequest(@RequestBody Map<String, Object> body,
                                                       @AuthenticationPrincipal CustomUserDetails principal,
                                                       HttpServletRequest request) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }

        // 限流（按用户维度）
        String rateKey = principal.getUsername();
        if (!rateLimit.allow("recharge", rateKey)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.fail("Too many requests, please try again later"));
        }

        // 解析金额
        Object amountObj = body.get("amount");
        double amount;
        try {
            amount = amountObj == null ? 0.0 : Double.parseDouble(amountObj.toString());
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.fail("Amount must be a positive number"));
        }
        if (amount <= 0) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.fail("Amount must be a positive number"));
        }
        if (amount > MAX_RECHARGE_AMOUNT) {
            return ResponseEntity.badRequest()
                    .body(ApiResponse.fail("Amount too large (max " + MAX_RECHARGE_AMOUNT + ")"));
        }

        String username = principal.getUsername();
        String uid = principal.getUid();
        String requestId = generateRequestId();

        RechargeRequest rr = new RechargeRequest();
        rr.setRequestId(requestId);
        rr.setUserUid(uid);
        rr.setUserName(username);
        rr.setAmount(amount);
        rr.setStatus("pending");
        rr.setCreatedAt(LocalDateTime.now());
        rechargeRepository.save(rr);

        log.info("Recharge request created: {} for user={} amount={}", requestId, username, amount);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Recharge request submitted", Map.of(
                        "request_id", requestId,
                        "amount", amount,
                        "status", "pending"
                )));
    }

    /**
     * 查看我的充值请求。
     * 对齐 Python /api/recharge/my-requests：支持 status 过滤 + 分页。
     */
    @GetMapping("/api/recharge/my-requests")
    public ResponseEntity<ApiResponse> myRechargeRequests(
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "limit", defaultValue = "20") int limit,
            @RequestParam(value = "offset", defaultValue = "0") int offset,
            @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }

        // 限制分页大小
        limit = Math.max(1, Math.min(limit, 100));
        offset = Math.max(0, offset);
        String uid = principal.getUid();

        PageRequest pageRequest = PageRequest.of(offset / limit, limit,
                Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<RechargeRequest> page;
        if (status != null && !status.isBlank()
                && (status.equals("pending") || status.equals("approved") || status.equals("rejected"))) {
            page = rechargeRepository.findByUserUidAndStatus(uid, status, pageRequest);
        } else {
            page = rechargeRepository.findByUserUid(uid, pageRequest);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("requests", page.getContent());
        data.put("total", page.getTotalElements());
        return ResponseEntity.ok(ApiResponse.ok(data));
    }

    /**
     * 获取余额变动记录。
     * 对齐 Python /api/transactions：支持 type 过滤 + 分页。
     */
    @GetMapping("/api/transactions")
    public ResponseEntity<ApiResponse> myTransactions(
            @RequestParam(value = "type", required = false) String type,
            @RequestParam(value = "page", defaultValue = "1") int page,
            @RequestParam(value = "page_size", defaultValue = "20") int pageSize,
            @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.fail("Not logged in"));
        }

        page = Math.max(1, page);
        pageSize = Math.max(1, Math.min(pageSize, 100));
        String uid = principal.getUid();

        PageRequest pageRequest = PageRequest.of(page - 1, pageSize,
                Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<BalenceTransaction> txPage;
        if (type != null && !type.isBlank()) {
            txPage = transactionRepository.findByUserUidAndType(uid, type, pageRequest);
        } else {
            txPage = transactionRepository.findByUserUid(uid, pageRequest);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("transactions", txPage.getContent());
        data.put("total", txPage.getTotalElements());
        data.put("page", page);
        data.put("page_size", pageSize);
        return ResponseEntity.ok(ApiResponse.ok(data));
    }

    // ---------- 辅助 ----------

    /** 生成充值请求 ID（对齐 Python _generate_request_id: 'rcr_' + uuid hex） */
    private static String generateRequestId() {
        return "rcr_" + UUID.randomUUID().toString().replace("-", "");
    }
}

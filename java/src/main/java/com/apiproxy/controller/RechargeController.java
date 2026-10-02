package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.entity.BalenceTransaction;
import com.apiproxy.entity.RechargeRequest;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.RechargeService;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 充值 Controller。
 *
 * 对应 Python routes/recharge.py：
 * - POST /api/recharge/create           创建充值订单
 * - GET  /api/recharge/status/{orderId} 查询充值状态
 * - POST /api/recharge/callback          支付回调（模拟）
 * - GET  /api/recharge/history           充值记录
 * - GET  /api/recharge/transactions      交易记录
 * - GET  /api/admin/recharges            管理员：所有充值
 * - POST /api/admin/recharges/{id}/review 管理员：审核充值
 */
@RestController
public class RechargeController {

    private final RechargeService rechargeService;

    public RechargeController(RechargeService rechargeService) {
        this.rechargeService = rechargeService;
    }

    // ---------- 用户端 ----------

    @PostMapping("/api/recharge/create")
    public ResponseEntity<ApiResponse> createRecharge(
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(ApiResponse.fail("Not logged in"));
        }
        double amount = Double.parseDouble(str(body.get("amount")));
        String paymentMethod = str(body.get("payment_method"));
        try {
            Map<String, Object> result = rechargeService.createRecharge(
                    principal.getUsername(), amount, paymentMethod);
            return ResponseEntity.ok(ApiResponse.ok("Recharge order created", result));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @GetMapping("/api/recharge/status/{orderId}")
    public ResponseEntity<ApiResponse> rechargeStatus(@PathVariable String orderId) {
        try {
            RechargeRequest req = rechargeService.getRechargeStatus(orderId);
            return ResponseEntity.ok(ApiResponse.ok(Map.of(
                    "order_id", req.getRequestId(),
                    "amount", req.getAmount(),
                    "status", req.getStatus(),
                    "created_at", req.getCreatedAt()
            )));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @PostMapping("/api/recharge/callback")
    public ResponseEntity<ApiResponse> rechargeCallback(@RequestBody Map<String, Object> body) {
        String orderId = str(body.get("order_id"));
        String status = str(body.get("status"));
        String transactionId = str(body.get("transaction_id"));
        try {
            rechargeService.processCallback(orderId, status, transactionId);
            return ResponseEntity.ok(ApiResponse.ok("Callback processed"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    @GetMapping("/api/recharge/history")
    public ResponseEntity<ApiResponse> rechargeHistory(
            @AuthenticationPrincipal CustomUserDetails principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        if (principal == null) {
            return ResponseEntity.status(401).body(ApiResponse.fail("Not logged in"));
        }
        Page<RechargeRequest> list = rechargeService.listUserRecharges(
                principal.getUsername(), page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    @GetMapping("/api/recharge/transactions")
    public ResponseEntity<ApiResponse> transactions(
            @AuthenticationPrincipal CustomUserDetails principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        if (principal == null) {
            return ResponseEntity.status(401).body(ApiResponse.fail("Not logged in"));
        }
        Page<BalenceTransaction> list = rechargeService.listTransactions(
                principal.getUsername(), page, size);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    // ---------- 管理员端 ----------

    @GetMapping("/api/admin/recharges")
    public ResponseEntity<ApiResponse> allRecharges(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String status) {
        Page<RechargeRequest> list = rechargeService.listAllRecharges(page, size, status);
        return ResponseEntity.ok(ApiResponse.ok(Map.of(
                "items", list.getContent(),
                "total", list.getTotalElements()
        )));
    }

    @PostMapping("/api/admin/recharges/{orderId}/review")
    public ResponseEntity<ApiResponse> reviewRecharge(
            @PathVariable String orderId,
            @RequestBody Map<String, Object> body,
            @AuthenticationPrincipal CustomUserDetails principal) {
        boolean approved = Boolean.TRUE.equals(body.get("approved"));
        String note = str(body.get("note"));
        try {
            rechargeService.adminReview(orderId, approved, principal.getUsername(), note);
            return ResponseEntity.ok(ApiResponse.ok(approved ? "Recharge approved" : "Recharge rejected"));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(ApiResponse.fail(e.getMessage()));
        }
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString().trim();
    }
}

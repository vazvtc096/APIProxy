package com.apiproxy.service;

import com.apiproxy.entity.BalenceTransaction;
import com.apiproxy.entity.RechargeRequest;
import com.apiproxy.entity.User;
import com.apiproxy.repository.BalenceTransactionRepository;
import com.apiproxy.repository.RechargeRequestRepository;
import com.apiproxy.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 充值服务。
 *
 * 对应 Python routes/recharge.py + core_billing.py。
 * RechargeRequest: requestId / userUid / userName / amount(Double) / status / processedAt；
 * BalenceTransaction: transactionId / userUid / userName / type / amount(Double) / balenceAfter / relatedId / remark；
 * User: userName / balence(Double) / uid。
 */
@Service
public class RechargeService {

    private static final Logger log = LoggerFactory.getLogger(RechargeService.class);

    private final RechargeRequestRepository rechargeRequestRepository;
    private final BalenceTransactionRepository balenceTransactionRepository;
    private final UserRepository userRepository;

    public RechargeService(RechargeRequestRepository rechargeRequestRepository,
                           BalenceTransactionRepository balenceTransactionRepository,
                           UserRepository userRepository) {
        this.rechargeRequestRepository = rechargeRequestRepository;
        this.balenceTransactionRepository = balenceTransactionRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public Map<String, Object> createRecharge(String username, double amount, String paymentMethod) {
        if (amount <= 0) {
            throw new IllegalArgumentException("Invalid amount");
        }
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String orderId = "RC" + System.currentTimeMillis() + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        RechargeRequest req = new RechargeRequest();
        req.setRequestId(orderId);
        req.setUserUid(user.getUid());
        req.setUserName(username);
        req.setAmount(amount);
        req.setStatus("pending");
        req.setCreatedAt(LocalDateTime.now());
        rechargeRequestRepository.save(req);

        log.info("Recharge created: {} user={} amount={}", orderId, username, amount);
        return Map.of(
                "order_id", orderId,
                "amount", amount,
                "payment_method", paymentMethod != null ? paymentMethod : "alipay",
                "status", "pending"
        );
    }

    @Transactional
    public void processCallback(String orderId, String status, String transactionId) {
        RechargeRequest req = rechargeRequestRepository.findAll().stream()
                .filter(r -> orderId.equals(r.getRequestId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Order not found"));
        if (!"pending".equals(req.getStatus())) {
            throw new IllegalStateException("Order already processed");
        }
        if ("success".equals(status)) {
            req.setStatus("completed");
            req.setProcessedAt(LocalDateTime.now());
            rechargeRequestRepository.save(req);
            addBalance(req.getUserUid(), req.getUserName(), req.getAmount(),
                    "recharge:" + orderId);
            log.info("Recharge completed: {} amount={}", orderId, req.getAmount());
        } else {
            req.setStatus("failed");
            req.setAdminRemark(status);
            rechargeRequestRepository.save(req);
            log.warn("Recharge failed: {} reason={}", orderId, status);
        }
    }

    @Transactional
    public void addBalance(String userUid, String username, double amount, String reason) {
        User user = userRepository.findByUid(userUid)
                .orElseGet(() -> userRepository.findByUserName(username).orElse(null));
        if (user == null) throw new IllegalArgumentException("User not found");
        double oldBalance = user.getBalence() != null ? user.getBalence() : 0.0;
        user.setBalence(oldBalance + amount);
        userRepository.save(user);

        BalenceTransaction tx = new BalenceTransaction();
        tx.setTransactionId("TX" + System.currentTimeMillis());
        tx.setUserUid(userUid);
        tx.setUserName(username);
        tx.setType("credit");
        tx.setAmount(amount);
        tx.setBalenceAfter(user.getBalence());
        tx.setRelatedId(reason);
        tx.setRemark(reason);
        tx.setCreatedAt(LocalDateTime.now());
        balenceTransactionRepository.save(tx);
    }

    @Transactional
    public boolean deductBalance(String userUid, String username, double amount, String reason) {
        User user = userRepository.findByUid(userUid)
                .orElseGet(() -> userRepository.findByUserName(username).orElse(null));
        if (user == null) throw new IllegalArgumentException("User not found");
        double oldBalance = user.getBalence() != null ? user.getBalence() : 0.0;
        if (oldBalance < amount) {
            return false;
        }
        user.setBalence(oldBalance - amount);
        userRepository.save(user);

        BalenceTransaction tx = new BalenceTransaction();
        tx.setTransactionId("TX" + System.currentTimeMillis());
        tx.setUserUid(userUid);
        tx.setUserName(username);
        tx.setType("debit");
        tx.setAmount(amount);
        tx.setBalenceAfter(user.getBalence());
        tx.setRelatedId(reason);
        tx.setRemark(reason);
        tx.setCreatedAt(LocalDateTime.now());
        balenceTransactionRepository.save(tx);
        return true;
    }

    public RechargeRequest getRechargeStatus(String orderId) {
        return rechargeRequestRepository.findAll().stream()
                .filter(r -> orderId.equals(r.getRequestId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Order not found"));
    }

    public Page<RechargeRequest> listUserRecharges(String username, int page, int size) {
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null || user.getUid() == null) {
            return Page.empty();
        }
        return rechargeRequestRepository.findByUserUid(user.getUid(),
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    public Page<BalenceTransaction> listTransactions(String username, int page, int size) {
        User user = userRepository.findByUserName(username).orElse(null);
        if (user == null || user.getUid() == null) {
            return Page.empty();
        }
        return balenceTransactionRepository.findByUserUid(user.getUid(),
                PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    public Page<RechargeRequest> listAllRecharges(int page, int size, String status) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        if (status != null && !status.isBlank()) {
            List<RechargeRequest> all = rechargeRequestRepository.findByStatusOrderByCreatedAtDesc(status);
            return paginate(all, pr);
        }
        return rechargeRequestRepository.findAll(pr);
    }

    @Transactional
    public void adminReview(String orderId, boolean approved, String adminUser, String note) {
        RechargeRequest req = rechargeRequestRepository.findAll().stream()
                .filter(r -> orderId.equals(r.getRequestId()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Order not found"));
        if (!"pending".equals(req.getStatus())) {
            throw new IllegalStateException("Order already processed");
        }
        User admin = userRepository.findByUserName(adminUser).orElse(null);
        req.setAdminName(adminUser);
        if (admin != null) req.setAdminUid(admin.getUid());
        if (approved) {
            processCallback(orderId, "success", "admin:" + adminUser);
        } else {
            req.setStatus("rejected");
            req.setAdminRemark(note);
            req.setProcessedAt(LocalDateTime.now());
            rechargeRequestRepository.save(req);
            log.warn("Recharge rejected by {}: {}", adminUser, orderId);
        }
    }

    private static <T> Page<T> paginate(List<T> list, PageRequest pr) {
        int start = (int) pr.getOffset();
        int end = Math.min(start + pr.getPageSize(), list.size());
        return new org.springframework.data.domain.PageImpl<>(
                start < list.size() ? list.subList(start, end) : List.of(),
                pr, list.size());
    }
}

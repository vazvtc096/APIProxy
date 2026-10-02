package com.apiproxy.service;

import com.apiproxy.entity.AuditLog;
import com.apiproxy.entity.LoginLog;
import com.apiproxy.entity.WebAccessLog;
import com.apiproxy.repository.AuditLogRepository;
import com.apiproxy.repository.LoginLogRepository;
import com.apiproxy.repository.WebAccessLogRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 审计服务。
 *
 * 对应 Python routes/audit_routes.py + audit_server.py。
 * 字段对齐实际 Entity：AuditLog.eventType / AuditLog.userName / AuditLog.clientIp 等。
 */
@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final LoginLogRepository loginLogRepository;
    private final WebAccessLogRepository webAccessLogRepository;

    public AuditService(AuditLogRepository auditLogRepository,
                        LoginLogRepository loginLogRepository,
                        WebAccessLogRepository webAccessLogRepository) {
        this.auditLogRepository = auditLogRepository;
        this.loginLogRepository = loginLogRepository;
        this.webAccessLogRepository = webAccessLogRepository;
    }

    // ---------- 审计日志 ----------

    @Transactional
    public void logAudit(String username, String action, String resource,
                         String ip, String userAgent, String details) {
        AuditLog log = new AuditLog();
        log.setUserName(username);
        log.setEventType(action);
        log.setSeverity("info");
        log.setClientIp(ip);
        log.setDetails(details != null ? details : "resource=" + resource);
        log.setCreatedAt(LocalDateTime.now());
        auditLogRepository.save(log);
    }

    public Page<AuditLog> queryAuditLogs(String username, String action,
                                          String resource, int page, int size) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        List<AuditLog> all = auditLogRepository.findAll();
        List<AuditLog> filtered = all.stream()
                .filter(l -> username == null || username.isBlank() || username.equals(l.getUserName()))
                .filter(l -> action == null || action.isBlank() || action.equals(l.getEventType()))
                .toList();
        return paginate(filtered, pr);
    }

    // ---------- 登录日志 ----------

    @Transactional
    public void logLogin(String username, boolean success, String ip,
                         String userAgent, String failureReason) {
        LoginLog log = new LoginLog();
        log.setUserName(username);
        log.setLoginIp(ip);
        log.setUserAgent(userAgent);
        log.setStatus(success ? "success" : "failed");
        log.setReason(failureReason);
        log.setCreatedAt(LocalDateTime.now());
        loginLogRepository.save(log);
    }

    public Page<LoginLog> queryLoginLogs(String username, Boolean success,
                                          int page, int size) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        List<LoginLog> all = loginLogRepository.findAll();
        List<LoginLog> filtered = all.stream()
                .filter(l -> username == null || username.isBlank() || username.equals(l.getUserName()))
                .filter(l -> success == null || (success ? "success".equals(l.getStatus()) : "failed".equals(l.getStatus())))
                .toList();
        return paginate(filtered, pr);
    }

    // ---------- Web 访问日志 ----------

    @Transactional
    public void logWebAccess(String ip, String method, String path,
                             int status, long responseTime, String userAgent,
                             String username) {
        WebAccessLog log = new WebAccessLog();
        log.setClientIp(ip);
        log.setMethod(method);
        log.setPath(path);
        log.setStatus(status);
        log.setUserName(username);
        log.setCreatedAt(LocalDateTime.now());
        webAccessLogRepository.save(log);
    }

    public Page<WebAccessLog> queryWebAccessLogs(String ip, String path,
                                                  Integer status, int page, int size) {
        PageRequest pr = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        List<WebAccessLog> all = webAccessLogRepository.findAll();
        List<WebAccessLog> filtered = all.stream()
                .filter(l -> ip == null || ip.isBlank() || ip.equals(l.getClientIp()))
                .filter(l -> path == null || path.isBlank() || (l.getPath() != null && l.getPath().contains(path)))
                .filter(l -> status == null || status.equals(l.getStatus()))
                .toList();
        return paginate(filtered, pr);
    }

    /** 统计：指定时间后的请求数 */
    public long countRequestsSince(LocalDateTime since) {
        return webAccessLogRepository.findAll().stream()
                .filter(l -> l.getCreatedAt() != null && l.getCreatedAt().isAfter(since))
                .count();
    }

    /** 统计：指定时间后的唯一 IP 数 */
    public long countUniqueIpsSince(LocalDateTime since) {
        return webAccessLogRepository.findAll().stream()
                .filter(l -> l.getCreatedAt() != null && l.getCreatedAt().isAfter(since))
                .map(WebAccessLog::getClientIp)
                .distinct()
                .count();
    }

    // ---------- 工具 ----------

    private static <T> Page<T> paginate(List<T> list, PageRequest pr) {
        int start = (int) pr.getOffset();
        int end = Math.min(start + pr.getPageSize(), list.size());
        return new org.springframework.data.domain.PageImpl<>(
                start < list.size() ? list.subList(start, end) : List.of(),
                pr, list.size());
    }
}

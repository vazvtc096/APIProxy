package com.apiproxy.controller;

import com.apiproxy.common.ApiResponse;
import com.apiproxy.security.ids.IdsIpsService;
import com.apiproxy.security.waf.WafService;
import com.apiproxy.security.webfilter.WebFilterService;
import com.apiproxy.service.SchedulerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 安全与基础设施管理 Controller。
 *
 * 暴露 WAF / IDS-IPS / WebFilter / Scheduler 的状态查询和运行期配置端点。
 * 对应 Python console_routes.py 中的 waf/ids/webfilter/scheduler 管理命令。
 */
@RestController
@RequestMapping("/api/security")
public class SecurityController {

    private final WafService wafService;
    private final IdsIpsService idsIpsService;
    private final WebFilterService webFilterService;
    private final SchedulerService schedulerService;

    public SecurityController(WafService wafService,
                              IdsIpsService idsIpsService,
                              WebFilterService webFilterService,
                              SchedulerService schedulerService) {
        this.wafService = wafService;
        this.idsIpsService = idsIpsService;
        this.webFilterService = webFilterService;
        this.schedulerService = schedulerService;
    }

    // ---------- WAF ----------

    @GetMapping("/waf/status")
    public ResponseEntity<ApiResponse> wafStatus() {
        return ResponseEntity.ok(ApiResponse.ok(wafService.getStatus()));
    }

    @PostMapping("/waf/toggle")
    public ResponseEntity<ApiResponse> wafToggle(@RequestBody Map<String, Object> body) {
        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        wafService.setWafEnabled(enabled);
        return ResponseEntity.ok(ApiResponse.ok("WAF " + (enabled ? "enabled" : "disabled")));
    }

    // ---------- IDS/IPS ----------

    @GetMapping("/ids/status")
    public ResponseEntity<ApiResponse> idsStatus() {
        return ResponseEntity.ok(ApiResponse.ok(idsIpsService.getStatus()));
    }

    @PostMapping("/ids/toggle")
    public ResponseEntity<ApiResponse> idsToggle(@RequestBody Map<String, Object> body) {
        boolean enabled = Boolean.TRUE.equals(body.get("enabled"));
        idsIpsService.setEnabled(enabled);
        return ResponseEntity.ok(ApiResponse.ok("IDS/IPS " + (enabled ? "enabled" : "disabled")));
    }

    @PostMapping("/ids/mode")
    public ResponseEntity<ApiResponse> idsMode(@RequestBody Map<String, Object> body) {
        String mode = (String) body.get("mode");
        idsIpsService.setMode(mode);
        return ResponseEntity.ok(ApiResponse.ok("IDS/IPS mode set to " + mode));
    }

    // ---------- WebFilter ----------

    @GetMapping("/webfilter/status")
    public ResponseEntity<ApiResponse> webFilterStatus() {
        return ResponseEntity.ok(ApiResponse.ok(webFilterService.getStatus()));
    }

    @GetMapping("/webfilter/categories")
    public ResponseEntity<ApiResponse> webFilterCategories() {
        return ResponseEntity.ok(ApiResponse.ok(webFilterService.getCategories()));
    }

    @PostMapping("/webfilter/block")
    public ResponseEntity<ApiResponse> webFilterAddBlock(@RequestBody Map<String, Object> body) {
        String category = (String) body.get("category");
        webFilterService.addBlock(category);
        return ResponseEntity.ok(ApiResponse.ok("Category " + category + " added to block list"));
    }

    @PostMapping("/webfilter/unblock")
    public ResponseEntity<ApiResponse> webFilterRemoveBlock(@RequestBody Map<String, Object> body) {
        String category = (String) body.get("category");
        webFilterService.removeBlock(category);
        return ResponseEntity.ok(ApiResponse.ok("Category " + category + " removed from block list"));
    }

    // ---------- Scheduler ----------

    @GetMapping("/scheduler/status")
    public ResponseEntity<ApiResponse> schedulerStatus() {
        return ResponseEntity.ok(ApiResponse.ok(schedulerService.getStatus()));
    }

    @GetMapping("/scheduler/tasks")
    public ResponseEntity<ApiResponse> schedulerTasks() {
        return ResponseEntity.ok(ApiResponse.ok(schedulerService.listTasks()));
    }

    @PostMapping("/scheduler/tasks/{id}/trigger")
    public ResponseEntity<ApiResponse> schedulerTrigger(@PathVariable Long id) {
        schedulerService.triggerTask(id);
        return ResponseEntity.ok(ApiResponse.ok("Task triggered"));
    }

    @GetMapping("/scheduler/tasks/{id}/logs")
    public ResponseEntity<ApiResponse> schedulerLogs(
            @PathVariable Long id,
            @RequestParam(defaultValue = "20") int limit) {
        return ResponseEntity.ok(ApiResponse.ok(schedulerService.listLogs(id, limit)));
    }
}

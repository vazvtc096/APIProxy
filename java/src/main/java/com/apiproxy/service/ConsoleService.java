package com.apiproxy.service;

import com.apiproxy.entity.ConfigKv;
import com.apiproxy.entity.SystemConfig;
import com.apiproxy.repository.ConfigKvRepository;
import com.apiproxy.repository.SystemConfigRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.lang.management.ManagementFactory;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

/**
 * 控制台服务。
 *
 * 对应 Python core_console.py + routes/console_routes.py。
 * ConfigKv: key / value；SystemConfig: key / value / updatedAt。
 */
@Service
public class ConsoleService {

    private static final Logger log = LoggerFactory.getLogger(ConsoleService.class);

    private final ConfigKvRepository configKvRepository;
    private final SystemConfigRepository systemConfigRepository;

    public ConsoleService(ConfigKvRepository configKvRepository,
                          SystemConfigRepository systemConfigRepository) {
        this.configKvRepository = configKvRepository;
        this.systemConfigRepository = systemConfigRepository;
    }

    public List<ConfigKv> listAllConfigs() {
        return configKvRepository.findAll();
    }

    public String getConfig(String key) {
        return configKvRepository.findById(key)
                .map(ConfigKv::getValue)
                .orElse(null);
    }

    @Transactional
    public void setConfig(String key, String value) {
        ConfigKv cfg = configKvRepository.findById(key)
                .orElseGet(() -> {
                    ConfigKv c = new ConfigKv();
                    c.setKey(key);
                    return c;
                });
        cfg.setValue(value);
        configKvRepository.save(cfg);
        log.info("Console config updated: {}={}", key, value);
    }

    @Transactional
    public void deleteConfig(String key) {
        configKvRepository.deleteById(key);
    }

    public List<SystemConfig> listSystemConfigs() {
        return systemConfigRepository.findAll();
    }

    @Transactional
    public void updateSystemConfig(String key, String value, String description) {
        SystemConfig cfg = systemConfigRepository.findById(key)
                .orElseGet(() -> {
                    SystemConfig c = new SystemConfig();
                    c.setKey(key);
                    return c;
                });
        cfg.setValue(value);
        cfg.setUpdatedAt(LocalDateTime.now());
        systemConfigRepository.save(cfg);
    }

    public Map<String, Object> getSystemInfo() {
        Runtime rt = Runtime.getRuntime();
        return Map.of(
                "java_version", System.getProperty("java.version"),
                "java_vendor", System.getProperty("java.vendor"),
                "os_name", System.getProperty("os.name"),
                "os_arch", System.getProperty("os.arch"),
                "processors", rt.availableProcessors(),
                "max_memory_mb", rt.maxMemory() / (1024 * 1024),
                "total_memory_mb", rt.totalMemory() / (1024 * 1024),
                "free_memory_mb", rt.freeMemory() / (1024 * 1024),
                "used_memory_mb", (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024),
                "uptime_ms", ManagementFactory.getRuntimeMXBean().getUptime()
        );
    }

    private static final List<String> ALLOWED_COMMANDS = List.of(
            "status", "config.list", "config.get", "config.set",
            "system.info", "health"
    );

    public Map<String, Object> executeCommand(String command, Map<String, Object> args) {
        if (!ALLOWED_COMMANDS.contains(command)) {
            throw new IllegalArgumentException("Unknown command: " + command);
        }
        return switch (command) {
            case "status" -> Map.of("status", "running", "timestamp", LocalDateTime.now().toString());
            case "config.list" -> Map.of("configs", listAllConfigs());
            case "config.get" -> Map.of("value", getConfig(str(args.get("key"))));
            case "config.set" -> {
                setConfig(str(args.get("key")), str(args.get("value")));
                yield Map.of("result", "ok");
            }
            case "system.info" -> getSystemInfo();
            case "health" -> Map.of("health", "ok");
            default -> throw new IllegalArgumentException("Command not implemented: " + command);
        };
    }

    private static String str(Object o) {
        return o == null ? "" : o.toString();
    }
}

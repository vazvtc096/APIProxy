package com.apiproxy.service;

import com.apiproxy.entity.ConfigKv;
import com.apiproxy.repository.ConfigKvRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 集群服务。
 *
 * 对应 Python cluster.py + core_net_utils.py。
 * ConfigKv 实体字段：key / value（String 主键）。
 */
@Service
public class ClusterService {

    private static final Logger log = LoggerFactory.getLogger(ClusterService.class);
    private static final long HEARTBEAT_TIMEOUT = 30;

    private final ConfigKvRepository configKvRepository;

    @Value("${apiproxy.cluster.node-id:node-1}")
    private String nodeId;

    @Value("${apiproxy.cluster.enabled:false}")
    private boolean clusterEnabled;

    private final Map<String, NodeInfo> nodes = new ConcurrentHashMap<>();

    public ClusterService(ConfigKvRepository configKvRepository) {
        this.configKvRepository = configKvRepository;
    }

    public void registerNode(String host, int port) {
        NodeInfo info = new NodeInfo(nodeId, host, port, Instant.now().getEpochSecond(), false);
        nodes.put(nodeId, info);
        saveClusterConfig("node:" + nodeId,
                String.format("{\"host\":\"%s\",\"port\":%d,\"lastSeen\":%d}",
                        host, port, info.lastSeen()));
        log.info("Node {} registered at {}:{}", nodeId, host, port);
    }

    public void heartbeat() {
        NodeInfo info = nodes.get(nodeId);
        if (info != null) {
            NodeInfo updated = new NodeInfo(info.nodeId(), info.host(), info.port(),
                    Instant.now().getEpochSecond(), info.isLeader());
            nodes.put(nodeId, updated);
        }
    }

    public List<NodeInfo> getActiveNodes() {
        long now = Instant.now().getEpochSecond();
        return nodes.values().stream()
                .filter(n -> now - n.lastSeen() < HEARTBEAT_TIMEOUT)
                .toList();
    }

    public Map<String, Object> getClusterStatus() {
        List<NodeInfo> active = getActiveNodes();
        return Map.of(
                "enabled", clusterEnabled,
                "node_id", nodeId,
                "active_nodes", active.size(),
                "nodes", active,
                "timestamp", Instant.now().toString()
        );
    }

    public String electLeader() {
        List<NodeInfo> active = getActiveNodes();
        if (active.isEmpty()) return null;
        return active.stream()
                .map(NodeInfo::nodeId)
                .min(String::compareTo)
                .orElse(null);
    }

    public boolean isLeader() {
        String leader = electLeader();
        return nodeId.equals(leader);
    }

    public void syncClusterConfig() {
        List<ConfigKv> configs = configKvRepository.findAll();
        long now = Instant.now().getEpochSecond();
        for (ConfigKv cfg : configs) {
            if (cfg.getKey() != null && cfg.getKey().startsWith("node:")) {
                String id = cfg.getKey().substring("node:".length());
                if (!id.equals(nodeId)) {
                    try {
                        String val = cfg.getValue();
                        String host = extractJsonString(val, "host");
                        int port = Integer.parseInt(extractJsonString(val, "port"));
                        long lastSeen = Long.parseLong(extractJsonString(val, "lastSeen"));
                        if (now - lastSeen < HEARTBEAT_TIMEOUT) {
                            nodes.put(id, new NodeInfo(id, host, port, lastSeen, false));
                        } else {
                            nodes.remove(id);
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
    }

    private void saveClusterConfig(String key, String value) {
        ConfigKv cfg = configKvRepository.findById(key)
                .orElseGet(() -> {
                    ConfigKv c = new ConfigKv();
                    c.setKey(key);
                    return c;
                });
        cfg.setValue(value);
        configKvRepository.save(cfg);
    }

    private static String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start < 0) {
            pattern = "\"" + key + "\":";
            start = json.indexOf(pattern);
            if (start < 0) return "";
            start += pattern.length();
            int end = json.indexOf(",", start);
            if (end < 0) end = json.indexOf("}", start);
            return json.substring(start, end).trim();
        }
        start += pattern.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    public record NodeInfo(String nodeId, String host, int port, long lastSeen, boolean isLeader) {}
}

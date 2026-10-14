package com.apiproxy.service;

import com.apiproxy.entity.DebugConsoleConfig;
import com.apiproxy.entity.DebugConsoleKeys;
import com.apiproxy.repository.DebugConsoleConfigRepository;
import com.apiproxy.repository.DebugConsoleKeysRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Debug Console 服务。
 *
 * 对应 Python debugConsole.py + debug_console_client.py + debug_console_crypto.py + core_debug_console.py。
 * DebugConsoleConfig: id(Long) / name / host / port / password / enabled(Integer)；
 * DebugConsoleKeys: id(Long) / keyHash / keyName / isActive(Integer)。
 */
@Service
public class DebugConsoleService {

    private static final Logger log = LoggerFactory.getLogger(DebugConsoleService.class);
    private static final int TIMEOUT_MS = 5000;

    private final DebugConsoleConfigRepository debugConsoleConfigRepository;
    private final DebugConsoleKeysRepository debugConsoleKeysRepository;

    @Value("${apiproxy.debug_console.enabled:true}")
    private boolean debugConsoleEnabled;

    private final Map<String, DebugConsoleSession> sessions = new ConcurrentHashMap<>();

    public DebugConsoleService(DebugConsoleConfigRepository debugConsoleConfigRepository,
                       DebugConsoleKeysRepository debugConsoleKeysRepository) {
        this.debugConsoleConfigRepository = debugConsoleConfigRepository;
        this.debugConsoleKeysRepository = debugConsoleKeysRepository;
    }

    public List<DebugConsoleConfig> listConfigs() {
        return debugConsoleConfigRepository.findAllByOrderByIdAsc();
    }

    @Transactional
    public DebugConsoleConfig createConfig(String name, String host, int port, String password) {
        DebugConsoleConfig cfg = new DebugConsoleConfig();
        cfg.setName(name);
        cfg.setHost(host);
        cfg.setPort(port);
        cfg.setPassword(encryptPassword(password));
        cfg.setEnabled(1);
        cfg.setCreatedAt(LocalDateTime.now());
        cfg.setUpdatedAt(LocalDateTime.now());
        return debugConsoleConfigRepository.save(cfg);
    }

    @Transactional
    public void deleteConfig(Long id) {
        debugConsoleConfigRepository.deleteById(id);
    }

    public List<DebugConsoleKeys> listKeys() {
        return debugConsoleKeysRepository.findAllByOrderByCreatedAtDesc();
    }

    @Transactional
    public DebugConsoleKeys generateKey(String name, String permission) {
        String rawKey = "debugConsole_" + java.util.UUID.randomUUID().toString().replace("-", "");
        String keyHash = java.security.MessageDigest.isEqual(new byte[0], new byte[0])
                ? rawKey : rawKey; // placeholder
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            keyHash = Base64.getEncoder().encodeToString(md.digest(rawKey.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) {}
        DebugConsoleKeys debugConsoleKey = new DebugConsoleKeys();
        debugConsoleKey.setKeyHash(keyHash);
        debugConsoleKey.setKeyName(name);
        debugConsoleKey.setIsActive(1);
        debugConsoleKey.setCreatedAt(LocalDateTime.now());
        return debugConsoleKeysRepository.save(debugConsoleKey);
    }

    public boolean validateKey(String apiKey) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            String hash = Base64.getEncoder().encodeToString(md.digest(apiKey.getBytes(StandardCharsets.UTF_8)));
            return debugConsoleKeysRepository.findByKeyHashAndIsActive(hash, 1).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    public String executeCommand(String host, int port, String password, String command) {
        if (!debugConsoleEnabled) {
            throw new IllegalStateException("Debug Console is disabled");
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            byte[] loginPacket = buildDebugConsolePacket(3, password);
            socket.getOutputStream().write(loginPacket);
            socket.getOutputStream().flush();
            byte[] loginResp = readDebugConsolePacket(socket);
            if (loginResp == null || !isAuthSuccess(loginResp)) {
                throw new SecurityException("Debug Console authentication failed");
            }
            byte[] cmdPacket = buildDebugConsolePacket(2, command);
            socket.getOutputStream().write(cmdPacket);
            socket.getOutputStream().flush();
            byte[] respPacket = readDebugConsolePacket(socket);
            if (respPacket != null) {
                return extractBody(respPacket);
            }
            return "";
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            log.error("Debug Console command failed: {} -> {}", host, e.getMessage());
            throw new IllegalStateException("Debug Console command failed: " + e.getMessage());
        }
    }

    public String executeByConfigId(Long configId, String command) {
        DebugConsoleConfig cfg = debugConsoleConfigRepository.findById(configId)
                .orElseThrow(() -> new IllegalArgumentException("Debug Console config not found"));
        if (cfg.getEnabled() == null || cfg.getEnabled() != 1) {
            throw new IllegalStateException("Debug Console config is disabled");
        }
        String password = decryptPassword(cfg.getPassword());
        return executeCommand(cfg.getHost(), cfg.getPort(), password, command);
    }

    public String createSession(String host, int port, String password) {
        executeCommand(host, port, password, "list");
        String sessionId = java.util.UUID.randomUUID().toString();
        sessions.put(sessionId, new DebugConsoleSession(host, port, encryptPassword(password),
                true, System.currentTimeMillis() / 1000));
        return sessionId;
    }

    public String executeInSession(String sessionId, String command) {
        DebugConsoleSession session = sessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("Invalid Debug Console session");
        }
        if (System.currentTimeMillis() / 1000 - session.lastActivity() > 300) {
            sessions.remove(sessionId);
            throw new IllegalStateException("Debug Console session expired");
        }
        String password = decryptPassword(session.encryptedPassword());
        String result = executeCommand(session.host(), session.port(), password, command);
        sessions.put(sessionId, new DebugConsoleSession(session.host(), session.port(),
                session.encryptedPassword(), true, System.currentTimeMillis() / 1000));
        return result;
    }

    public void closeSession(String sessionId) {
        sessions.remove(sessionId);
    }

    // ---------- Debug Console 协议工具 ----------

    private byte[] buildDebugConsolePacket(int type, String body) {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        int packetSize = 4 + 4 + bodyBytes.length + 2;
        byte[] packet = new byte[packetSize + 4];
        writeIntLE(packet, 0, packetSize);
        writeIntLE(packet, 4, (int) (Math.random() * Integer.MAX_VALUE));
        writeIntLE(packet, 8, type);
        System.arraycopy(bodyBytes, 0, packet, 12, bodyBytes.length);
        return packet;
    }

    private byte[] readDebugConsolePacket(Socket socket) throws Exception {
        byte[] sizeBuf = new byte[4];
        int read = socket.getInputStream().read(sizeBuf);
        if (read < 4) return null;
        int size = readIntLE(sizeBuf, 0);
        if (size > 4096) return null;
        byte[] packet = new byte[size];
        int totalRead = 0;
        while (totalRead < size) {
            int r = socket.getInputStream().read(packet, totalRead, size - totalRead);
            if (r < 0) break;
            totalRead += r;
        }
        return packet;
    }

    private boolean isAuthSuccess(byte[] packet) {
        int id = readIntLE(packet, 0);
        return id != -1;
    }

    private String extractBody(byte[] packet) {
        int end = 8;
        while (end < packet.length && packet[end] != 0) end++;
        return new String(packet, 8, end - 8, StandardCharsets.UTF_8);
    }

    private static void writeIntLE(byte[] buf, int offset, int value) {
        buf[offset] = (byte) (value & 0xFF);
        buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
        buf[offset + 2] = (byte) ((value >> 16) & 0xFF);
        buf[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static int readIntLE(byte[] buf, int offset) {
        return (buf[offset] & 0xFF)
                | ((buf[offset + 1] & 0xFF) << 8)
                | ((buf[offset + 2] & 0xFF) << 16)
                | ((buf[offset + 3] & 0xFF) << 24);
    }

    // ---------- 加密 ----------

    private static final String AES_KEY = "DebugConsoleKey1";

    private String encryptPassword(String password) {
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    private String decryptPassword(String encrypted) {
        try {
            SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(StandardCharsets.UTF_8), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    public record DebugConsoleSession(String host, int port, String encryptedPassword,
                              boolean authenticated, long lastActivity) {}
}

package com.apiproxy.service;

import com.apiproxy.entity.RconConfig;
import com.apiproxy.entity.RconKeys;
import com.apiproxy.repository.RconConfigRepository;
import com.apiproxy.repository.RconKeysRepository;
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
 * RCON 服务。
 *
 * 对应 Python rcon.py + rcon_client.py + rcon_crypto.py + core_rcon.py。
 * RconConfig: id(Long) / name / host / port / password / enabled(Integer)；
 * RconKeys: id(Long) / keyHash / keyName / isActive(Integer)。
 */
@Service
public class RconService {

    private static final Logger log = LoggerFactory.getLogger(RconService.class);
    private static final int TIMEOUT_MS = 5000;

    private final RconConfigRepository rconConfigRepository;
    private final RconKeysRepository rconKeysRepository;

    @Value("${apiproxy.rcon.enabled:true}")
    private boolean rconEnabled;

    private final Map<String, RconSession> sessions = new ConcurrentHashMap<>();

    public RconService(RconConfigRepository rconConfigRepository,
                       RconKeysRepository rconKeysRepository) {
        this.rconConfigRepository = rconConfigRepository;
        this.rconKeysRepository = rconKeysRepository;
    }

    public List<RconConfig> listConfigs() {
        return rconConfigRepository.findAllByOrderByIdAsc();
    }

    @Transactional
    public RconConfig createConfig(String name, String host, int port, String password) {
        RconConfig cfg = new RconConfig();
        cfg.setName(name);
        cfg.setHost(host);
        cfg.setPort(port);
        cfg.setPassword(encryptPassword(password));
        cfg.setEnabled(1);
        cfg.setCreatedAt(LocalDateTime.now());
        cfg.setUpdatedAt(LocalDateTime.now());
        return rconConfigRepository.save(cfg);
    }

    @Transactional
    public void deleteConfig(Long id) {
        rconConfigRepository.deleteById(id);
    }

    public List<RconKeys> listKeys() {
        return rconKeysRepository.findAllByOrderByCreatedAtDesc();
    }

    @Transactional
    public RconKeys generateKey(String name, String permission) {
        String rawKey = "rcon_" + java.util.UUID.randomUUID().toString().replace("-", "");
        String keyHash = java.security.MessageDigest.isEqual(new byte[0], new byte[0])
                ? rawKey : rawKey; // placeholder
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            keyHash = Base64.getEncoder().encodeToString(md.digest(rawKey.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ignored) {}
        RconKeys rconKey = new RconKeys();
        rconKey.setKeyHash(keyHash);
        rconKey.setKeyName(name);
        rconKey.setIsActive(1);
        rconKey.setCreatedAt(LocalDateTime.now());
        return rconKeysRepository.save(rconKey);
    }

    public boolean validateKey(String apiKey) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            String hash = Base64.getEncoder().encodeToString(md.digest(apiKey.getBytes(StandardCharsets.UTF_8)));
            return rconKeysRepository.findByKeyHashAndIsActive(hash, 1).isPresent();
        } catch (Exception e) {
            return false;
        }
    }

    public String executeCommand(String host, int port, String password, String command) {
        if (!rconEnabled) {
            throw new IllegalStateException("RCON is disabled");
        }
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            byte[] loginPacket = buildRconPacket(3, password);
            socket.getOutputStream().write(loginPacket);
            socket.getOutputStream().flush();
            byte[] loginResp = readRconPacket(socket);
            if (loginResp == null || !isAuthSuccess(loginResp)) {
                throw new SecurityException("RCON authentication failed");
            }
            byte[] cmdPacket = buildRconPacket(2, command);
            socket.getOutputStream().write(cmdPacket);
            socket.getOutputStream().flush();
            byte[] respPacket = readRconPacket(socket);
            if (respPacket != null) {
                return extractBody(respPacket);
            }
            return "";
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            log.error("RCON command failed: {} -> {}", host, e.getMessage());
            throw new IllegalStateException("RCON command failed: " + e.getMessage());
        }
    }

    public String executeByConfigId(Long configId, String command) {
        RconConfig cfg = rconConfigRepository.findById(configId)
                .orElseThrow(() -> new IllegalArgumentException("RCON config not found"));
        if (cfg.getEnabled() == null || cfg.getEnabled() != 1) {
            throw new IllegalStateException("RCON config is disabled");
        }
        String password = decryptPassword(cfg.getPassword());
        return executeCommand(cfg.getHost(), cfg.getPort(), password, command);
    }

    public String createSession(String host, int port, String password) {
        executeCommand(host, port, password, "list");
        String sessionId = java.util.UUID.randomUUID().toString();
        sessions.put(sessionId, new RconSession(host, port, encryptPassword(password),
                true, System.currentTimeMillis() / 1000));
        return sessionId;
    }

    public String executeInSession(String sessionId, String command) {
        RconSession session = sessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("Invalid RCON session");
        }
        if (System.currentTimeMillis() / 1000 - session.lastActivity() > 300) {
            sessions.remove(sessionId);
            throw new IllegalStateException("RCON session expired");
        }
        String password = decryptPassword(session.encryptedPassword());
        String result = executeCommand(session.host(), session.port(), password, command);
        sessions.put(sessionId, new RconSession(session.host(), session.port(),
                session.encryptedPassword(), true, System.currentTimeMillis() / 1000));
        return result;
    }

    public void closeSession(String sessionId) {
        sessions.remove(sessionId);
    }

    // ---------- RCON 协议工具 ----------

    private byte[] buildRconPacket(int type, String body) {
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        int packetSize = 4 + 4 + bodyBytes.length + 2;
        byte[] packet = new byte[packetSize + 4];
        writeIntLE(packet, 0, packetSize);
        writeIntLE(packet, 4, (int) (Math.random() * Integer.MAX_VALUE));
        writeIntLE(packet, 8, type);
        System.arraycopy(bodyBytes, 0, packet, 12, bodyBytes.length);
        return packet;
    }

    private byte[] readRconPacket(Socket socket) throws Exception {
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

    private static final String AES_KEY = "APIProxyRCONKey1";

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

    public record RconSession(String host, int port, String encryptedPassword,
                              boolean authenticated, long lastActivity) {}
}

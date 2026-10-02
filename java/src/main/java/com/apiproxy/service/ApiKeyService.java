package com.apiproxy.service;

import com.apiproxy.entity.Apikey;
import com.apiproxy.entity.User;
import com.apiproxy.repository.ApikeyRepository;
import com.apiproxy.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * API Key 服务：生成 / 验证 / 列表 / 删除。
 *
 * 对应 Python apikey.py 的 APIKey 类与 _gen_and_save_apikey 辅助函数。
 *
 * 业务规则（对齐 Python 版）：
 * - 格式：sk- + 48 位十六进制（24 字节熵，SecureRandom）
 * - 存储：SHA256 哈希存入 apikeys 表（防明文泄露），同时追加到 users.apikeys 逗号分隔字段（向后兼容）
 * - 限制：每用户最多 10 个 API Key
 * - 验证：通过 apikeys 表哈希索引查找（O(1)），命中后更新 last_used_at
 */
@Service
public class ApiKeyService {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyService.class);

    private static final int MAX_KEYS_PER_USER = 10;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private final ApikeyRepository apikeyRepository;
    private final UserRepository userRepository;

    public ApiKeyService(ApikeyRepository apikeyRepository, UserRepository userRepository) {
        this.apikeyRepository = apikeyRepository;
        this.userRepository = userRepository;
    }

    /**
     * 为已登录用户生成新的 API Key（trusted 模式，无需密码验证）。
     * 对齐 Python APIKey._require_apikey_trusted → _gen_and_save_apikey。
     *
     * @param username 已认证用户名
     * @return 明文 API Key 字符串（sk-... 格式）
     */
    @Transactional
    public String generateApiKey(String username) {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<String> existing = parseApiKeys(user.getApikeys());
        if (existing.size() >= MAX_KEYS_PER_USER) {
            throw new IllegalStateException("Maximum " + MAX_KEYS_PER_USER + " API keys per user");
        }

        // 生成唯一 Key（最多重试 10 次，对齐 Python _gen_and_save_apikey）
        for (int i = 0; i < 10; i++) {
            String newKey = generateKeyString();
            if (existing.contains(newKey)) continue;

            // 追加到 users.apikeys（向后兼容 Python 版逗号分隔字段）
            existing.add(newKey);
            user.setApikeys(String.join(",", existing));
            userRepository.save(user);

            // 写入索引表（仅存哈希，防明文泄露）
            Apikey apikey = new Apikey();
            apikey.setApikeyHash(sha256(newKey));
            apikey.setOwnerName(username);
            apikey.setOwnerUid(user.getUid());
            apikey.setCreatedAt(LocalDateTime.now());
            apikeyRepository.save(apikey);

            log.info("API key generated for user: {}", username);
            return newKey;
        }
        throw new IllegalStateException("Failed to generate a unique API key after 10 attempts");
    }

    /**
     * 通过 API Key 查找关联用户（trusted 模式）。
     * 对齐 Python APIKey._get_user_by_apikey / from_apikey。
     *
     * @param apiKey 明文 API Key
     * @return 关联用户；格式无效或未找到返回 Optional.empty()
     */
    public Optional<User> verifyApiKey(String apiKey) {
        if (!isValidFormat(apiKey)) return Optional.empty();
        String hash = sha256(apiKey);
        Optional<Apikey> opt = apikeyRepository.findByApikeyHash(hash);
        if (opt.isEmpty()) return Optional.empty();
        Apikey ak = opt.get();
        Optional<User> userOpt = userRepository.findByUserName(ak.getOwnerName());
        if (userOpt.isPresent()) {
            // 更新 last_used_at（异步容忍失败）
            try {
                apikeyRepository.updateLastUsedAt(hash, LocalDateTime.now());
            } catch (Exception e) {
                log.warn("updateLastUsedAt failed for {}: {}", ak.getOwnerName(), e.getMessage());
            }
        }
        return userOpt;
    }

    /**
     * 列出用户的所有 API Key（返回元数据，不含明文 Key）。
     * 对齐 Python 用户中心 API Key 列表。
     */
    public List<Map<String, Object>> listApiKeys(String username) {
        List<Apikey> keys = apikeyRepository.findByOwnerName(username);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Apikey ak : keys) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", ak.getId());
            m.put("apikey_hash", ak.getApikeyHash());
            m.put("owner_name", ak.getOwnerName());
            m.put("created_at", ak.getCreatedAt());
            m.put("last_used_at", ak.getLastUsedAt());
            result.add(m);
        }
        return result;
    }

    /**
     * 删除指定 API Key（仅允许 Key 所属用户删除）。
     * 对齐 Python APIKey.delete。
     *
     * @param username 当前认证用户
     * @param apiKey   待删除的明文 API Key
     * @return true 删除成功；false Key 不存在或不属于该用户
     */
    @Transactional
    public boolean deleteApiKey(String username, String apiKey) {
        if (!isValidFormat(apiKey)) return false;
        String hash = sha256(apiKey);
        Optional<Apikey> opt = apikeyRepository.findByApikeyHash(hash);
        if (opt.isEmpty()) return false;
        Apikey ak = opt.get();
        if (!username.equals(ak.getOwnerName())) return false;

        // 从索引表删除
        apikeyRepository.delete(ak);

        // 从 users.apikeys 逗号分隔字段移除（向后兼容）
        User user = userRepository.findByUserName(username).orElse(null);
        if (user != null) {
            List<String> existing = parseApiKeys(user.getApikeys());
            existing.remove(apiKey);
            user.setApikeys(String.join(",", existing));
            userRepository.save(user);
        }

        log.info("API key deleted for user: {}", username);
        return true;
    }

    // ---------- 辅助 ----------

    /** 验证 API Key 格式：sk- + 48 位（新）或 32 位（旧兼容）十六进制 */
    private static boolean isValidFormat(String apiKey) {
        if (apiKey == null || !apiKey.startsWith("sk-")) return false;
        String keyPart = apiKey.substring(3);
        if (keyPart.length() != 32 && keyPart.length() != 48) return false;
        for (char c : keyPart.toCharArray()) {
            if ("0123456789abcdef".indexOf(c) < 0) return false;
        }
        return true;
    }

    /** 生成 API Key：sk- + 48 位完全随机十六进制（24 字节熵，对齐 Python secrets.token_hex(24)） */
    private static String generateKeyString() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        char[] chars = new char[48];
        for (int i = 0; i < 24; i++) {
            int v = bytes[i] & 0xFF;
            chars[i * 2] = HEX[v >>> 4];
            chars[i * 2 + 1] = HEX[v & 0x0F];
        }
        return "sk-" + new String(chars);
    }

    /** SHA256 哈希（对齐 Python _hash_apikey） */
    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            char[] chars = new char[hash.length * 2];
            for (int i = 0; i < hash.length; i++) {
                int v = hash[i] & 0xFF;
                chars[i * 2] = HEX[v >>> 4];
                chars[i * 2 + 1] = HEX[v & 0x0F];
            }
            return new String(chars);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /** 解析 users.apikeys 逗号分隔字段 */
    private static List<String> parseApiKeys(String apikeysStr) {
        if (apikeysStr == null || apikeysStr.isBlank()) return new ArrayList<>();
        List<String> keys = new ArrayList<>(Arrays.asList(apikeysStr.split(",")));
        keys.removeIf(String::isBlank);
        return keys;
    }
}

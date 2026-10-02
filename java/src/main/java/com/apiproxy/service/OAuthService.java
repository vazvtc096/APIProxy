package com.apiproxy.service;

import com.apiproxy.entity.OauthAuthCode;
import com.apiproxy.entity.OauthClient;
import com.apiproxy.entity.OauthDeviceCode;
import com.apiproxy.entity.OauthToken;
import com.apiproxy.repository.OauthAuthCodeRepository;
import com.apiproxy.repository.OauthClientRepository;
import com.apiproxy.repository.OauthDeviceCodeRepository;
import com.apiproxy.repository.OauthTokenRepository;
import com.apiproxy.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * OAuth 2.0 授权服务器核心服务。
 *
 * 对应 Python oauth.py（核心逻辑）+ core_oauth.py（Bearer 校验 / scope 映射）。
 * 实现 RFC 6749 授权码 + PKCE、客户端凭证、刷新令牌，附 RFC 7009 吊销 / RFC 7662 内省 /
 * RFC 8628 设备授权流。
 *
 * access token 为 HS256 JWT（无状态验签），refresh token 为不透明随机串并落库
 * （oauth_tokens 表）以支持吊销/内省。JWT 密钥读自 application.yml 的
 * apiproxy.oauth.jwt-secret（对应 Python OAUTH_JWT_SECRET），未配置时 fail-closed 拒绝签发。
 */
@Service
public class OAuthService {

    private static final Logger log = LoggerFactory.getLogger(OAuthService.class);

    // 对齐 Python oauth.py 常量
    public static final long ACCESS_TOKEN_TTL = 3600;        // access token 有效期：1 小时
    public static final long REFRESH_TOKEN_TTL = 30L * 86400; // refresh token 有效期：30 天
    public static final long AUTH_CODE_TTL = 600;            // 授权码有效期：10 分钟
    public static final long DEVICE_CODE_TTL = 600;          // 设备码有效期：10 分钟
    public static final int DEVICE_INTERVAL = 5;             // 设备流轮询间隔（秒）

    private static final String DEFAULT_SCOPE = "api";
    private static final String USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ23456789";
    private static final char[] CODE_ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final OauthClientRepository clientRepository;
    private final OauthTokenRepository tokenRepository;
    private final OauthAuthCodeRepository authCodeRepository;
    private final OauthDeviceCodeRepository deviceCodeRepository;
    private final UserRepository userRepository;
    private final String jwtSecret;

    public OAuthService(OauthClientRepository clientRepository,
                        OauthTokenRepository tokenRepository,
                        OauthAuthCodeRepository authCodeRepository,
                        OauthDeviceCodeRepository deviceCodeRepository,
                        UserRepository userRepository,
                        @Value("${apiproxy.oauth.jwt-secret:}") String jwtSecret) {
        this.clientRepository = clientRepository;
        this.tokenRepository = tokenRepository;
        this.authCodeRepository = authCodeRepository;
        this.deviceCodeRepository = deviceCodeRepository;
        this.userRepository = userRepository;
        this.jwtSecret = jwtSecret;
    }

    // ==================== 客户端 ====================

    public Optional<OauthClient> getClient(String clientId) {
        if (clientId == null || clientId.isBlank()) return Optional.empty();
        return clientRepository.findByClientId(clientId);
    }

    /**
     * 校验客户端身份（对齐 Python authenticate_client）：confidential 客户端必须提供
     * 正确的 client_secret（与 client_secret_hash 的 SHA-256 十六进制比对）；public 客户端无需 secret。
     */
    public Optional<OauthClient> authenticateClient(String clientId, String clientSecret) {
        if (clientId == null || clientId.isBlank()) return Optional.empty();
        Optional<OauthClient> opt = clientRepository.findByClientId(clientId);
        if (opt.isEmpty()) return Optional.empty();
        OauthClient client = opt.get();
        if (client.getIsConfidential() != null && client.getIsConfidential() == 1) {
            if (clientSecret == null || clientSecret.isEmpty()) return Optional.empty();
            String stored = client.getClientSecretHash() == null ? "" : client.getClientSecretHash();
            if (!constantTimeEquals(sha256Hex(clientSecret), stored)) return Optional.empty();
        }
        return opt;
    }

    /** redirect_uri 是否在客户端注册列表中（逗号分隔，精确匹配） */
    public boolean clientAllowsRedirectUri(OauthClient client, String redirectUri) {
        if (client == null || client.getRedirectUris() == null || redirectUri == null) return false;
        for (String u : client.getRedirectUris().split(",")) {
            if (redirectUri.equals(u.trim())) return true;
        }
        return false;
    }

    // ==================== scope 工具 ====================

    /** 归一化 scope 字符串（去空、去重、保序） */
    public String normalizeScope(String scope) {
        if (scope == null || scope.isBlank()) return "";
        Set<String> seen = new LinkedHashSet<>();
        for (String s : scope.trim().split("\\s+")) {
            if (!s.isEmpty()) seen.add(s);
        }
        return String.join(" ", seen);
    }

    /** 请求的 scope 是否为客户端允许 scope 的子集 */
    public boolean scopeSubset(String requested, String allowed) {
        Set<String> req = new LinkedHashSet<>();
        if (requested != null) {
            for (String s : requested.trim().split("\\s+")) {
                if (!s.isEmpty()) req.add(s);
            }
        }
        Set<String> allow = new LinkedHashSet<>();
        if (allowed != null) {
            for (String s : allowed.trim().split("\\s+")) {
                if (!s.isEmpty()) allow.add(s);
            }
        }
        return allow.containsAll(req);
    }

    /** PKCE 校验（RFC 7636）：plain 或 S256（SHA-256 + base64url 无填充） */
    public boolean pkceVerify(String codeVerifier, String codeChallenge, String method) {
        if (codeVerifier == null || codeVerifier.isEmpty() || codeChallenge == null || codeChallenge.isEmpty()) {
            return false;
        }
        String m = (method == null || method.isBlank()) ? "plain" : method.toLowerCase();
        if ("plain".equals(m)) return constantTimeEquals(codeVerifier, codeChallenge);
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return constantTimeEquals(challenge, codeChallenge);
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    // ==================== 授权码 ====================

    /**
     * 创建授权码（8 位随机，落库 oauth_auth_codes，有效期 10 分钟）。
     * code_challenge 非空时强制 S256 PKCE。
     */
    @Transactional
    public String createAuthorizationCode(String clientId, String redirectUri, String scopes,
                                          String username, String uid, String codeChallenge) {
        String code = generateAuthCode();
        OauthAuthCode ac = new OauthAuthCode();
        ac.setCode(code);
        ac.setClientId(clientId);
        ac.setRedirectUri(redirectUri);
        ac.setScope(scopes);
        ac.setUserName(username);
        ac.setUserUid(uid);
        if (codeChallenge != null && !codeChallenge.isBlank()) {
            ac.setCodeChallenge(codeChallenge);
            ac.setCodeChallengeMethod("s256");
        }
        ac.setExpiresAt(nowEpochSeconds() + AUTH_CODE_TTL);
        ac.setUsed(0);
        ac.setCreatedAt(LocalDateTime.now());
        authCodeRepository.save(ac);
        return code;
    }

    /** 授权码换 token（一次性消费 + PKCE 校验）。 */
    @Transactional
    public Map<String, Object> tokenFromAuthorizationCode(String code, String clientId,
                                                          String redirectUri, String codeVerifier) {
        if (code == null || code.isBlank()) {
            throw new OAuthError("invalid_grant", "authorization code invalid or expired", 400);
        }
        OauthAuthCode row = authCodeRepository.findByCode(code)
                .orElseThrow(() -> new OAuthError("invalid_grant", "authorization code invalid or expired", 400));
        if (row.getUsed() != null && row.getUsed() == 1) {
            throw new OAuthError("invalid_grant", "authorization code invalid or expired", 400);
        }
        if (row.getExpiresAt() == null || row.getExpiresAt() < nowEpochSeconds()) {
            throw new OAuthError("invalid_grant", "authorization code invalid or expired", 400);
        }
        if (!row.getClientId().equals(clientId)) {
            throw new OAuthError("invalid_grant", null, 400);
        }
        if (redirectUri != null && !redirectUri.isBlank() && !redirectUri.equals(row.getRedirectUri())) {
            throw new OAuthError("invalid_grant", "redirect_uri mismatch", 400);
        }
        String challenge = row.getCodeChallenge();
        if (challenge != null && !challenge.isBlank()) {
            String method = row.getCodeChallengeMethod() == null ? "plain" : row.getCodeChallengeMethod();
            if (!pkceVerify(codeVerifier, challenge, method)) {
                throw new OAuthError("invalid_grant", "PKCE verification failed", 400);
            }
        }
        row.setUsed(1);
        authCodeRepository.save(row);
        return issueTokens(row.getClientId(), row.getUserUid(), row.getUserName(), row.getScope());
    }

    /** 刷新令牌换新 token 对（旧 refresh 立即吊销）。 */
    @Transactional
    public Map<String, Object> tokenFromRefreshToken(String refreshToken, String clientId) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new OAuthError("invalid_grant", "refresh token invalid or expired", 400);
        }
        OauthToken row = tokenRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new OAuthError("invalid_grant", "refresh token invalid or expired", 400));
        if (row.getRevoked() != null && row.getRevoked() == 1) {
            throw new OAuthError("invalid_grant", "refresh token invalid or expired", 400);
        }
        if (!row.getClientId().equals(clientId)) {
            throw new OAuthError("invalid_grant", null, 400);
        }
        if (row.getRefreshExpiresAt() == null || row.getRefreshExpiresAt() < nowEpochSeconds()) {
            throw new OAuthError("invalid_grant", "refresh token invalid or expired", 400);
        }
        row.setRevoked(1);
        tokenRepository.save(row);
        return issueTokens(row.getClientId(), row.getUserUid(), row.getUserName(), row.getScope() == null ? "" : row.getScope());
    }

    /**
     * 客户端凭证模式（RFC 6749 4.4）：需要客户端绑定计费账号（owner_name）。
     * scope 可选，缺省用客户端注册 scope。
     */
    @Transactional
    public Map<String, Object> tokenFromClientCredentials(String clientId, String clientSecret, String scope) {
        OauthClient client = authenticateClient(clientId, clientSecret)
                .orElseThrow(() -> new OAuthError("invalid_client", null, 401));
        String allowed = client.getScopes() == null ? "" : client.getScopes();
        String normalized = normalizeScope(scope);
        if (!normalized.isEmpty() && !scopeSubset(normalized, allowed)) {
            throw new OAuthError("invalid_scope", null, 400);
        }
        if (normalized.isEmpty()) normalized = allowed.isEmpty() ? DEFAULT_SCOPE : allowed;
        String owner = client.getOwnerName();
        if (owner == null || owner.isBlank()) {
            throw new OAuthError("invalid_grant", "client has no bound owner account", 400);
        }
        var userOpt = userRepository.findByUserName(owner);
        if (userOpt.isEmpty()) {
            throw new OAuthError("invalid_grant", "bound owner account not found", 400);
        }
        return issueTokens(clientId, userOpt.get().getUid(), owner, normalized);
    }

    // ==================== Token 签发 / 校验 / 吊销 / 内省 ====================

    /** 签发一组 token（access JWT + refresh 不透明串）并落库，返回响应字典。 */
    @Transactional
    public Map<String, Object> issueTokens(String clientId, String userUid, String userName, String scope) {
        SignedToken signed = signAccessToken(clientId, userUid, userName, scope);
        String refreshToken = generateRefreshToken();
        double now = nowEpochSeconds();
        OauthToken t = new OauthToken();
        t.setAccessJti(signed.jti());
        t.setRefreshToken(refreshToken);
        t.setClientId(clientId);
        t.setUserUid(userUid);
        t.setUserName(userName);
        t.setScope(scope);
        t.setAccessExpiresAt(signed.exp());
        t.setRefreshExpiresAt(now + REFRESH_TOKEN_TTL);
        t.setRevoked(0);
        t.setCreatedAt(LocalDateTime.now());
        tokenRepository.save(t);
        log.info("OAuth tokens issued: client={}, user={}", clientId, userName);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", signed.token());
        resp.put("refresh_token", refreshToken);
        resp.put("token_type", "Bearer");
        resp.put("expires_in", ACCESS_TOKEN_TTL);
        resp.put("scope", scope);
        return resp;
    }

    /**
     * 校验 Bearer access token（对齐 Python validate_bearer）：
     * 验签 → 过期检查 → 按 jti 查 oauth_tokens → revoked / access_expires_at 检查。
     */
    public Optional<OauthToken> validateBearer(String token) {
        if (token == null || token.isBlank()) return Optional.empty();
        Claims claims = decodeAccessToken(token);
        if (claims == null) return Optional.empty();
        if (claims.getExpiration() != null && claims.getExpiration().getTime() < System.currentTimeMillis()) {
            return Optional.empty();
        }
        String jti = claims.getId();
        if (jti == null || jti.isBlank()) return Optional.empty();
        Optional<OauthToken> row = tokenRepository.findByAccessJti(jti);
        if (row.isEmpty()) return Optional.empty();
        OauthToken t = row.get();
        if (t.getRevoked() != null && t.getRevoked() == 1) return Optional.empty();
        if (t.getAccessExpiresAt() == null || t.getAccessExpiresAt() < nowEpochSeconds()) return Optional.empty();
        return row;
    }

    /** RFC 7009：吊销 token（先按 refresh token，再按 access token 的 jti），始终成功。 */
    @Transactional
    public void revokeToken(String token) {
        if (token == null || token.isBlank()) return;
        tokenRepository.findByRefreshToken(token).ifPresent(t -> {
            t.setRevoked(1);
            tokenRepository.save(t);
        });
        Claims claims = decodeAccessToken(token);
        if (claims != null && claims.getId() != null) {
            tokenRepository.findByAccessJti(claims.getId()).ifPresent(t -> {
                t.setRevoked(1);
                tokenRepository.save(t);
            });
        }
    }

    /** RFC 7662：返回 token 内省结果（active / scope / client_id / username / sub / exp / iat）。 */
    public Map<String, Object> introspect(String token) {
        Map<String, Object> inactive = new LinkedHashMap<>();
        inactive.put("active", false);
        if (token == null || token.isBlank()) return inactive;
        Claims claims = decodeAccessToken(token);
        if (claims == null) return inactive;
        String jti = claims.getId();
        if (jti == null) return inactive;
        Optional<OauthToken> row = tokenRepository.findByAccessJti(jti);
        if (row.isEmpty()) return inactive;
        OauthToken t = row.get();
        if ((t.getRevoked() != null && t.getRevoked() == 1)
                || t.getAccessExpiresAt() == null || t.getAccessExpiresAt() < nowEpochSeconds()) {
            return inactive;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("active", true);
        out.put("scope", t.getScope() == null ? "" : t.getScope());
        out.put("client_id", t.getClientId());
        out.put("username", t.getUserName());
        out.put("sub", t.getUserUid());
        out.put("exp", t.getAccessExpiresAt().longValue());
        out.put("iat", claims.getIssuedAt() == null ? 0 : claims.getIssuedAt().getTime() / 1000);
        out.put("token_type", "Bearer");
        return out;
    }

    // ==================== 设备授权流（RFC 8628） ====================

    /** 创建设备码 + 用户码（有效期 10 分钟，轮询间隔 5 秒）。 */
    @Transactional
    public Map<String, Object> deviceAuthorization(String clientId, String scope) {
        String deviceCode = randomHex(32);
        String userCode = generateUserCode();
        double exp = nowEpochSeconds() + DEVICE_CODE_TTL;
        OauthDeviceCode dc = new OauthDeviceCode();
        dc.setDeviceCode(deviceCode);
        dc.setUserCode(userCode);
        dc.setClientId(clientId);
        dc.setScope(scope);
        dc.setExpiresAt(exp);
        dc.setInterval(DEVICE_INTERVAL);
        dc.setStatus("pending");
        dc.setCreatedAt(LocalDateTime.now());
        deviceCodeRepository.save(dc);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("device_code", deviceCode);
        resp.put("user_code", userCode);
        resp.put("verification_uri", "/oauth/device");
        resp.put("verification_uri_complete", "/oauth/device?user_code=" + userCode);
        resp.put("interval", DEVICE_INTERVAL);
        resp.put("expires_in", (long) (exp - nowEpochSeconds()));
        return resp;
    }

    /**
     * 设备流轮询（对齐 Python poll_device_code）：
     * status: "ok"（返回 token）/ "pending" / "error"（error 字段给出 RFC 8628 错误码）。
     */
    @Transactional
    public DevicePollResult deviceTokenPolling(String deviceCode, String clientId) {
        Optional<OauthDeviceCode> opt = deviceCodeRepository.findByDeviceCode(deviceCode);
        if (opt.isEmpty()) return new DevicePollResult("error", null, "invalid_grant");
        OauthDeviceCode row = opt.get();
        if (!row.getClientId().equals(clientId)) return new DevicePollResult("error", null, "invalid_grant");
        if (row.getExpiresAt() == null || row.getExpiresAt() < nowEpochSeconds()) {
            return new DevicePollResult("error", null, "expired_token");
        }
        String status = row.getStatus() == null ? "pending" : row.getStatus();
        switch (status) {
            case "approved": {
                row.setStatus("used");
                deviceCodeRepository.save(row);
                Map<String, Object> tokens = issueTokens(row.getClientId(), row.getUserUid(),
                        row.getUserName(), row.getScope() == null ? "" : row.getScope());
                return new DevicePollResult("ok", tokens, null);
            }
            case "denied":
                return new DevicePollResult("error", null, "access_denied");
            case "pending":
                return new DevicePollResult("pending", null, null);
            default:
                return new DevicePollResult("error", null, "invalid_grant");
        }
    }

    // ==================== JWT 签名 ====================

    /** 签发 HS256 access token，返回 token / jti / exp（epoch 秒）。 */
    private SignedToken signAccessToken(String clientId, String userUid, String userName, String scope) {
        long nowMs = System.currentTimeMillis();
        String jti = UUID.randomUUID().toString().replace("-", "");
        String sub = (userUid == null || userUid.isBlank()) ? clientId : userUid;
        String token = Jwts.builder()
                .issuer("APIProxy")
                .subject(sub)
                .audience().add(clientId).and()
                .expiration(new Date(nowMs + ACCESS_TOKEN_TTL * 1000))
                .issuedAt(new Date(nowMs))
                .id(jti)
                .claim("client_id", clientId)
                .claim("scope", scope == null ? "" : scope)
                .claim("username", userName == null ? "" : userName)
                .claim("token_type", "access")
                .signWith(signingKey(), Jwts.SIG.HS256)
                .compact();
        return new SignedToken(token, jti, nowMs / 1000.0 + ACCESS_TOKEN_TTL);
    }

    /** 解码并验签 access token，失败返回 null（不抛出，调用方判空）。 */
    private Claims decodeAccessToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            return null;
        }
    }

    /** fail-closed：未配置 OAUTH_JWT_SECRET 时拒绝签发/验签，绝不静默降级。 */
    private SecretKey signingKey() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException(
                    "OAUTH_JWT_SECRET is not configured. Refusing to sign/verify OAuth tokens (fail-closed). "
                    + "Set apiproxy.oauth.jwt-secret in application.yml or the OAUTH_JWT_SECRET env var.");
        }
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    // ==================== 内部辅助 ====================

    private String generateAuthCode() {
        // 8 位随机码；极低概率冲突时重试，仍冲突则退化为 16 位
        for (int attempt = 0; attempt < 3; attempt++) {
            String code = randomString(CODE_ALPHABET, 8);
            if (authCodeRepository.findByCode(code).isEmpty()) return code;
        }
        return randomString(CODE_ALPHABET, 16);
    }

    private String generateRefreshToken() {
        return randomHex(32);
    }

    private String generateUserCode() {
        // 形如 WDJB-MJHT，剔除易混淆字符
        return randomString(USER_CODE_ALPHABET.toCharArray(), 4) + "-"
                + randomString(USER_CODE_ALPHABET.toCharArray(), 4);
    }

    private static String randomString(char[] alphabet, int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append(alphabet[RANDOM.nextInt(alphabet.length)]);
        return sb.toString();
    }

    private static String randomHex(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) sb.append("0123456789abcdef".charAt(RANDOM.nextInt(16)));
        return sb.toString();
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        byte[] ba = (a == null ? "" : a).getBytes(StandardCharsets.UTF_8);
        byte[] bb = (b == null ? "" : b).getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(ba, bb);
    }

    private static double nowEpochSeconds() {
        return System.currentTimeMillis() / 1000.0;
    }

    /** access token 签名结果：token 串 + jti + 过期时间（epoch 秒） */
    private record SignedToken(String token, String jti, double exp) {}

    /** 设备流轮询结果：status=ok/pending/error；ok 时 tokens 非空，error 时 error 给出错误码 */
    public record DevicePollResult(String status, Map<String, Object> tokens, String error) {}

    /** OAuth 协议错误（error / error_description / HTTP status），由 Controller 转 JSON 响应 */
    public static class OAuthError extends RuntimeException {
        private final String error;
        private final String description;
        private final int status;

        public OAuthError(String error, String description, int status) {
            super(error);
            this.error = error;
            this.description = description;
            this.status = status;
        }

        public String getError() { return error; }
        public String getDescription() { return description; }
        public int getStatus() { return status; }
    }
}

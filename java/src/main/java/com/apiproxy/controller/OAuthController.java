package com.apiproxy.controller;

import com.apiproxy.entity.OauthClient;
import com.apiproxy.entity.OauthToken;
import com.apiproxy.security.CustomUserDetails;
import com.apiproxy.service.OAuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * OAuth 2.0 授权端点 Controller。
 *
 * 对应 Python routes/oauth_routes.py：
 * - GET/POST /oauth/authorize（授权码 + PKCE，含内置 'default' 公开客户端）
 * - POST /oauth/token（authorization_code / refresh_token / client_credentials）
 * - POST /oauth/revoke（RFC 7009）
 * - POST /oauth/introspect（RFC 7662）
 * - POST /oauth/device_authorization + /oauth/device/token（RFC 8628）
 * - GET /api/oauth/verify（Bearer token 资源访问校验）
 *
 * 注意：OAuth2 token 端点为公开端点（SecurityConfig permitAll），不使用 @AuthenticationPrincipal；
 * 客户端身份通过 client_id/client_secret 或 Basic 头认证。
 */
@RestController
public class OAuthController {

    private final OAuthService oauthService;

    public OAuthController(OAuthService oauthService) {
        this.oauthService = oauthService;
    }

    // ==================== /oauth/authorize ====================

    /**
     * 授权端点 GET：校验参数后，未登录返回 login_required，已登录渲染授权确认页。
     * - client_id 为空视为内置公开客户端 'default'（强制 PKCE，redirect_uri 可为任意 http(s) 绝对地址）
     * - 已注册客户端走标准授权码流程（redirect_uri 必须匹配、scope 必须为客户端 scope 子集）
     */
    @GetMapping("/oauth/authorize")
    public ResponseEntity<?> authorizeGet(@RequestParam Map<String, String> params,
                                          @AuthenticationPrincipal CustomUserDetails principal) {
        AuthorizeContext ctx;
        try {
            ctx = buildAuthorizeContext(params);
        } catch (AuthorizeFlowException e) {
            return e.response;
        }
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "login_required",
                    "error_description", "Authentication required to authorize the OAuth client"));
        }
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(renderConsentHtml(ctx, principal.getUsername()));
    }

    /**
     * 授权端点 POST：用户提交授权决定。decision=allow 时生成授权码并 302 回
     * redirect_uri?code=...&state=...，否则重定向 error=access_denied。
     */
    @PostMapping("/oauth/authorize")
    public ResponseEntity<?> authorizePost(@RequestParam Map<String, String> params,
                                           @AuthenticationPrincipal CustomUserDetails principal) {
        AuthorizeContext ctx;
        try {
            ctx = buildAuthorizeContext(params);
        } catch (AuthorizeFlowException e) {
            return e.response;
        }
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "login_required",
                    "error_description", "Authentication required to authorize the OAuth client"));
        }
        String decision = params.getOrDefault("decision", "");
        if ("allow".equalsIgnoreCase(decision)) {
            String code = oauthService.createAuthorizationCode(
                    ctx.clientId, ctx.redirectUri, ctx.scope,
                    principal.getUsername(), principal.getUid(), ctx.codeChallenge);
            String sep = ctx.redirectUri.contains("?") ? "&" : "?";
            StringBuilder loc = new StringBuilder(ctx.redirectUri).append(sep).append("code=").append(urlEncode(code));
            if (!ctx.state.isEmpty()) loc.append("&state=").append(urlEncode(ctx.state));
            return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(loc.toString())).build();
        }
        return redirectError(ctx.redirectUri, "access_denied", ctx.state);
    }

    // ==================== /oauth/token ====================

    /**
     * Token 端点（对齐 Python oauth_token）：授权码 + PKCE / 刷新令牌 / 客户端凭证。
     * 客户端认证支持表单 client_id/client_secret 与 HTTP Basic 头。
     */
    @PostMapping(value = "/oauth/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> token(@RequestParam Map<String, String> form,
                                                     @RequestHeader(value = "Authorization", required = false) String authorization) {
        String grantType = trim(form.get("grant_type"));
        String clientId = trim(form.get("client_id"));
        String clientSecret = form.get("client_secret");
        String[] basic = parseBasicAuth(authorization);
        if (basic != null) {
            if (clientId.isEmpty()) clientId = basic[0];
            if (clientSecret == null || clientSecret.isEmpty()) clientSecret = basic[1];
        }
        try {
            if (!GRANT_TYPES.contains(grantType)) {
                throw new OAuthService.OAuthError("unsupported_grant_type", null, 400);
            }
            Map<String, Object> tokens;
            switch (grantType) {
                case "authorization_code":
                    oauthService.authenticateClient(clientId, clientSecret)
                            .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
                    tokens = oauthService.tokenFromAuthorizationCode(
                            trim(form.get("code")), clientId, trim(form.get("redirect_uri")), form.get("code_verifier"));
                    break;
                case "refresh_token":
                    oauthService.authenticateClient(clientId, clientSecret)
                            .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
                    tokens = oauthService.tokenFromRefreshToken(trim(form.get("refresh_token")), clientId);
                    break;
                default: // client_credentials（服务内部自行认证客户端）
                    tokens = oauthService.tokenFromClientCredentials(clientId, clientSecret, trim(form.get("scope")));
                    break;
            }
            return ResponseEntity.ok(tokens);
        } catch (OAuthService.OAuthError e) {
            return ResponseEntity.status(e.getStatus()).body(errorBody(e));
        }
    }

    // ==================== /oauth/revoke ====================

    /** RFC 7009：吊销 token（refresh 或 access），始终返回 200。 */
    @PostMapping(value = "/oauth/revoke", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> revoke(@RequestParam Map<String, String> form,
                                                      @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = trim(form.get("token"));
        String clientId = trim(form.get("client_id"));
        String clientSecret = form.get("client_secret");
        String[] basic = parseBasicAuth(authorization);
        if (basic != null) {
            if (clientId.isEmpty()) clientId = basic[0];
            if (clientSecret == null || clientSecret.isEmpty()) clientSecret = basic[1];
        }
        try {
            if (!clientId.isEmpty()) {
                oauthService.authenticateClient(clientId, clientSecret)
                        .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
            }
            if (token.isEmpty()) throw new OAuthService.OAuthError("invalid_request", null, 400);
            oauthService.revokeToken(token);
            return ResponseEntity.ok(Map.of());
        } catch (OAuthService.OAuthError e) {
            return ResponseEntity.status(e.getStatus()).body(errorBody(e));
        }
    }

    // ==================== /oauth/introspect ====================

    /** RFC 7662：内省 token（需客户端认证；token 不属于该客户端时返回 inactive）。 */
    @PostMapping(value = "/oauth/introspect", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> introspect(@RequestParam Map<String, String> form,
                                                          @RequestHeader(value = "Authorization", required = false) String authorization) {
        String token = trim(form.get("token"));
        String clientId = trim(form.get("client_id"));
        String clientSecret = form.get("client_secret");
        String[] basic = parseBasicAuth(authorization);
        if (basic != null) {
            if (clientId.isEmpty()) clientId = basic[0];
            if (clientSecret == null || clientSecret.isEmpty()) clientSecret = basic[1];
        }
        try {
            oauthService.authenticateClient(clientId, clientSecret)
                    .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
            if (token.isEmpty()) throw new OAuthService.OAuthError("invalid_request", null, 400);
            Map<String, Object> result = oauthService.introspect(token);
            if (Boolean.TRUE.equals(result.get("active")) && !clientId.equals(result.get("client_id"))) {
                Map<String, Object> inactive = new LinkedHashMap<>();
                inactive.put("active", false);
                return ResponseEntity.ok(inactive);
            }
            return ResponseEntity.ok(result);
        } catch (OAuthService.OAuthError e) {
            return ResponseEntity.status(e.getStatus()).body(errorBody(e));
        }
    }

    // ==================== 设备授权流（RFC 8628） ====================

    /** 设备授权端点：创建 device_code / user_code。 */
    @PostMapping(value = "/oauth/device_authorization", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> deviceAuthorization(@RequestParam Map<String, String> form,
                                                                   @RequestHeader(value = "Authorization", required = false) String authorization) {
        String clientId = trim(form.get("client_id"));
        String clientSecret = form.get("client_secret");
        String[] basic = parseBasicAuth(authorization);
        if (basic != null) {
            if (clientId.isEmpty()) clientId = basic[0];
            if (clientSecret == null || clientSecret.isEmpty()) clientSecret = basic[1];
        }
        try {
            OauthClient client = oauthService.authenticateClient(clientId, clientSecret)
                    .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
            String scope = oauthService.normalizeScope(trim(form.get("scope")));
            String allowed = client.getScopes() == null ? "" : client.getScopes();
            if (!scope.isEmpty() && !oauthService.scopeSubset(scope, allowed)) {
                throw new OAuthService.OAuthError("invalid_scope", null, 400);
            }
            if (scope.isEmpty()) scope = allowed.isEmpty() ? "api" : allowed;
            return ResponseEntity.ok(oauthService.deviceAuthorization(clientId, scope));
        } catch (OAuthService.OAuthError e) {
            return ResponseEntity.status(e.getStatus()).body(errorBody(e));
        }
    }

    /** 设备流轮询端点：pending → authorization_pending；approved → 返回 token 对。 */
    @PostMapping(value = "/oauth/device/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Map<String, Object>> deviceToken(@RequestParam Map<String, String> form,
                                                           @RequestHeader(value = "Authorization", required = false) String authorization) {
        String clientId = trim(form.get("client_id"));
        String clientSecret = form.get("client_secret");
        String[] basic = parseBasicAuth(authorization);
        if (basic != null) {
            if (clientId.isEmpty()) clientId = basic[0];
            if (clientSecret == null || clientSecret.isEmpty()) clientSecret = basic[1];
        }
        try {
            oauthService.authenticateClient(clientId, clientSecret)
                    .orElseThrow(() -> new OAuthService.OAuthError("invalid_client", null, 401));
            String deviceCode = trim(form.get("device_code"));
            if (deviceCode.isEmpty()) throw new OAuthService.OAuthError("invalid_request", "device_code required", 400);
            OAuthService.DevicePollResult result = oauthService.deviceTokenPolling(deviceCode, clientId);
            if ("ok".equals(result.status())) return ResponseEntity.ok(result.tokens());
            String error = "pending".equals(result.status()) ? "authorization_pending" : result.error();
            throw new OAuthService.OAuthError(error, null, 400);
        } catch (OAuthService.OAuthError e) {
            return ResponseEntity.status(e.getStatus()).body(errorBody(e));
        }
    }

    // ==================== /api/oauth/verify ====================

    /** Bearer token 资源访问校验（公开端点，自行解析 Authorization 头）。 */
    @GetMapping("/api/oauth/verify")
    public ResponseEntity<Map<String, Object>> verify(@RequestHeader(value = "Authorization", required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                    "error", "invalid_token",
                    "error_description", "Bearer token required"));
        }
        String token = authorization.substring(7).trim();
        Optional<OauthToken> opt = oauthService.validateBearer(token);
        if (opt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_token"));
        }
        OauthToken row = opt.get();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("valid", true);
        body.put("client_id", row.getClientId());
        body.put("user_uid", row.getUserUid());
        body.put("user_name", row.getUserName());
        body.put("scope", row.getScope() == null ? "" : row.getScope());
        return ResponseEntity.ok(body);
    }

    // ==================== 内部辅助 ====================

    private static final Set<String> GRANT_TYPES =
            Set.of("authorization_code", "refresh_token", "client_credentials");

    private static final Set<String> CONSENT_HIDDEN_FIELDS =
            Set.of("client_id", "redirect_uri", "response_type", "scope", "state",
                   "code_challenge", "code_challenge_method");

    /** 授权端点校验后的上下文 */
    private record AuthorizeContext(String clientId, boolean isDefault, String redirectUri,
                                    String responseType, String scope, String state,
                                    String codeChallenge, String codeChallengeMethod) {}

    /**
     * 校验 /oauth/authorize 参数（对齐 Python oauth_authorize 前半段）。
     * 校验失败抛出 AuthorizeFlowException，其携带已构造好的响应（JSON 错误或重定向错误）。
     */
    private AuthorizeContext buildAuthorizeContext(Map<String, String> p) {
        String clientId = trim(p.get("client_id"));
        String redirectUri = trim(p.get("redirect_uri"));
        String responseType = trim(p.get("response_type"));
        String scope = trim(p.get("scope"));
        String state = trim(p.get("state"));
        String codeChallenge = trim(p.get("code_challenge"));
        String codeChallengeMethod = trim(p.get("code_challenge_method"));

        if (clientId.isEmpty()) clientId = "default";
        boolean isDefault = "default".equals(clientId);

        if (isDefault) {
            // 内置公开客户端：不校验 secret；redirect_uri 允许任意 http(s) 绝对地址；强制 PKCE
            oauthService.getClient("default")
                    .orElseThrow(() -> new AuthorizeFlowException(
                            jsonError(500, "server_error", "内置默认客户端未初始化")));
            if (redirectUri.isEmpty()) {
                throw new AuthorizeFlowException(jsonError(400, "invalid_request", "redirect_uri is required"));
            }
            if (!isAbsoluteHttpUri(redirectUri)) {
                throw new AuthorizeFlowException(jsonError(400, "invalid_redirect_uri",
                        "redirect_uri must be an absolute http(s) URL"));
            }
            if (codeChallenge.isEmpty()) {
                throw new AuthorizeFlowException(jsonError(400, "invalid_request",
                        "code_challenge is required (PKCE mandatory)"));
            }
            if (!responseType.isEmpty() && !"code".equals(responseType)) {
                throw new AuthorizeFlowException(redirectError(redirectUri, "unsupported_response_type", state));
            }
            scope = oauthService.normalizeScope(scope);
            if (scope.isEmpty()) scope = "api";
            return new AuthorizeContext(clientId, true, redirectUri, responseType, scope, state,
                    codeChallenge, codeChallengeMethod);
        }

        // 已注册客户端：标准授权码流程
        OauthClient client = oauthService.getClient(clientId)
                .orElseThrow(() -> new AuthorizeFlowException(jsonError(400, "invalid_client", "unknown client_id")));
        if (!oauthService.clientAllowsRedirectUri(client, redirectUri)) {
            throw new AuthorizeFlowException(jsonError(400, "invalid_redirect_uri", null));
        }
        if (!responseType.isEmpty() && !"code".equals(responseType)) {
            throw new AuthorizeFlowException(redirectError(redirectUri, "unsupported_response_type", state));
        }
        scope = oauthService.normalizeScope(scope);
        String allowed = client.getScopes() == null ? "" : client.getScopes();
        if (scope.isEmpty()) scope = allowed.isEmpty() ? "api" : allowed;
        if (!oauthService.scopeSubset(scope, allowed)) {
            throw new AuthorizeFlowException(redirectError(redirectUri, "invalid_scope", state));
        }
        return new AuthorizeContext(clientId, false, redirectUri, responseType, scope, state,
                codeChallenge, codeChallengeMethod);
    }

    /** 授权确认页（内联 HTML，回 POST /oauth/authorize；模板就绪后可换 Thymeleaf 渲染） */
    private static String renderConsentHtml(AuthorizeContext ctx, String username) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">")
          .append("<title>Authorize</title></head><body>")
          .append("<h1>Authorize ").append(esc(ctx.clientId)).append("</h1>")
          .append("<p>Signed in as <strong>").append(esc(username)).append("</strong></p>")
          .append("<p>The application requests the following scopes: <code>").append(esc(ctx.scope)).append("</code></p>")
          .append("<form method=\"post\" action=\"/oauth/authorize\">");
        for (String field : CONSENT_HIDDEN_FIELDS) {
            String value = switch (field) {
                case "client_id" -> ctx.clientId;
                case "redirect_uri" -> ctx.redirectUri;
                case "response_type" -> ctx.responseType;
                case "scope" -> ctx.scope;
                case "state" -> ctx.state;
                case "code_challenge" -> ctx.codeChallenge;
                default -> ctx.codeChallengeMethod;
            };
            sb.append("<input type=\"hidden\" name=\"").append(esc(field))
              .append("\" value=\"").append(esc(value)).append("\">");
        }
        sb.append("<button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button> ")
          .append("<button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button>")
          .append("</form></body></html>");
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private static boolean isAbsoluteHttpUri(String uri) {
        try {
            URI u = new URI(uri);
            String scheme = u.getScheme();
            return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) && u.getHost() != null;
        } catch (Exception e) {
            return false;
        }
    }

    /** RFC 6749 回调重定向错误：302 → redirect_uri?error=...&state=... */
    private static ResponseEntity<?> redirectError(String redirectUri, String error, String state) {
        String sep = redirectUri.contains("?") ? "&" : "?";
        StringBuilder loc = new StringBuilder(redirectUri).append(sep).append("error=").append(urlEncode(error));
        if (state != null && !state.isEmpty()) loc.append("&state=").append(urlEncode(state));
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(loc.toString())).build();
    }

    private static ResponseEntity<Map<String, Object>> jsonError(int status, String error, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null && !description.isEmpty()) body.put("error_description", description);
        return ResponseEntity.status(status).body(body);
    }

    private static Map<String, Object> errorBody(OAuthService.OAuthError e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.getError());
        if (e.getDescription() != null && !e.getDescription().isEmpty()) body.put("error_description", e.getDescription());
        return body;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }

    /** 解析 Authorization: Basic base64(client_id:client_secret) */
    private static String[] parseBasicAuth(String authorization) {
        if (authorization == null || !authorization.startsWith("Basic ")) return null;
        try {
            String decoded = new String(
                    Base64.getDecoder().decode(authorization.substring(6).trim()), StandardCharsets.UTF_8);
            int idx = decoded.indexOf(':');
            if (idx < 0) return null;
            return new String[]{decoded.substring(0, idx), decoded.substring(idx + 1)};
        } catch (Exception e) {
            return null;
        }
    }

    /** 授权流校验失败：携带已构造好的错误响应 */
    private static class AuthorizeFlowException extends RuntimeException {
        final ResponseEntity<?> response;
        AuthorizeFlowException(ResponseEntity<?> response) {
            this.response = response;
        }
    }
}

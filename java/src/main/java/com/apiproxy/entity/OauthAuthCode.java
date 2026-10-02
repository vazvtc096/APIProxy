package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * OAuth 2.0 授权码实体（含 PKCE），对应 oauth_auth_codes 表。
 */
@Data
@Entity
@Table(name = "oauth_auth_codes")
public class OauthAuthCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "code", unique = true)
    private String code;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "user_uid")
    private String userUid;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "scope")
    private String scope;

    @Column(name = "redirect_uri")
    private String redirectUri;

    @Column(name = "code_challenge")
    private String codeChallenge;

    @Column(name = "code_challenge_method")
    private String codeChallengeMethod;

    @Column(name = "expires_at")
    private Double expiresAt;

    @Column(name = "used")
    private Integer used;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

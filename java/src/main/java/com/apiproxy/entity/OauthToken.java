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
 * OAuth 2.0 令牌记录实体（支持吊销与内省），对应 oauth_tokens 表。
 */
@Data
@Entity
@Table(name = "oauth_tokens")
public class OauthToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "access_jti", unique = true)
    private String accessJti;

    @Column(name = "refresh_token", unique = true)
    private String refreshToken;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "user_uid")
    private String userUid;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "scope")
    private String scope;

    @Column(name = "access_expires_at")
    private Double accessExpiresAt;

    @Column(name = "refresh_expires_at")
    private Double refreshExpiresAt;

    @Column(name = "revoked")
    private Integer revoked;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

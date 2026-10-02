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
 * OAuth 2.0 客户端注册实体，对应 oauth_clients 表。
 */
@Data
@Entity
@Table(name = "oauth_clients")
public class OauthClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "client_id", unique = true)
    private String clientId;

    @Column(name = "client_secret_hash")
    private String clientSecretHash;

    @Column(name = "client_name")
    private String clientName;

    @Column(name = "owner_name")
    private String ownerName;

    @Column(name = "redirect_uris")
    private String redirectUris;

    @Column(name = "grant_types")
    private String grantTypes;

    @Column(name = "scopes")
    private String scopes;

    @Column(name = "is_confidential")
    private Integer isConfidential;

    @Column(name = "token_endpoint_auth_method")
    private String tokenEndpointAuthMethod;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

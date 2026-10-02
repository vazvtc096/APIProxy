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
 * OAuth 2.0 设备授权流（RFC 8628）实体，对应 oauth_device_codes 表。
 */
@Data
@Entity
@Table(name = "oauth_device_codes")
public class OauthDeviceCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "device_code", unique = true)
    private String deviceCode;

    @Column(name = "user_code", unique = true)
    private String userCode;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "scope")
    private String scope;

    @Column(name = "expires_at")
    private Double expiresAt;

    @Column(name = "\"interval\"")
    private Integer interval;

    @Column(name = "user_uid")
    private String userUid;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "status")
    private String status;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

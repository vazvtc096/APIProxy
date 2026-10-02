package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "user_password")
    private String userPassword;

    @Column(name = "apikeys")
    private String apikeys;

    @Column(name = "balence")
    private Double balence;

    @Column(name = "uid")
    private String uid;

    @Column(name = "created_at")
    private String createdAt;

    @Column(name = "is_admin")
    private Integer isAdmin;

    @Column(name = "is_banned")
    private Integer isBanned;

    @Column(name = "ban_reason")
    private String banReason;

    @Column(name = "ban_expire_at")
    private Double banExpireAt;

    @Column(name = "email")
    private String email;

    @Column(name = "last_device_type")
    private String lastDeviceType;

    @Column(name = "last_device_os")
    private String lastDeviceOs;

    @Column(name = "max_sessions")
    private Integer maxSessions;

    @Column(name = "max_overdraft")
    private Double maxOverdraft;

    @Column(name = "must_change_password")
    private Integer mustChangePassword;

    @Column(name = "last_active_time")
    private LocalDateTime lastActiveTime;

    @Column(name = "login_count")
    private Integer loginCount;

    @Column(name = "total_spent")
    private Double totalSpent;
}

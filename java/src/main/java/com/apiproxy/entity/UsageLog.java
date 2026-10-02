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
@Table(name = "usage_logs")
public class UsageLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "log_id")
    private String logId;

    @Column(name = "user_uid")
    private String userUid;

    @Column(name = "user_name")
    private String userName;

    @Column(name = "apikey_hash")
    private String apikeyHash;

    @Column(name = "model")
    private String model;

    @Column(name = "endpoint")
    private String endpoint;

    @Column(name = "input_tokens")
    private Integer inputTokens;

    @Column(name = "output_tokens")
    private Integer outputTokens;

    @Column(name = "total_tokens")
    private Integer totalTokens;

    @Column(name = "cost")
    private Double cost;

    @Column(name = "is_stream")
    private Integer isStream;

    @Column(name = "status")
    private String status;

    @Column(name = "upstream")
    private String upstream;

    @Column(name = "duration_ms")
    private Integer durationMs;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

package com.apiproxy.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "security_events")
public class SecurityEvents {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userUid;
    private String userName;
    private String eventType;
    private String severity;
    private Integer riskScore;
    private String details;
    private String clientIp;
    private String deviceInfo;
    private String actionTaken;
    private LocalDateTime createdAt;
}

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
@Table(name = "debug_console_keys")
public class DebugConsoleKeys {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String keyHash;
    private String keyName;
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;
    private String lastUsedIp;
    private Integer isActive;
}

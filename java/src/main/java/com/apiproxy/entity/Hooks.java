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
@Table(name = "hooks")
public class Hooks {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hookId;
    private String name;
    private String description;
    private String events;
    private String condition;
    private String actions;
    private Integer isEnabled;
    private Integer priority;
    private Integer runCount;
    private Integer matchCount;
    private Integer errorCount;
    private LocalDateTime lastRunAt;
    private String lastError;
    private String createdBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}

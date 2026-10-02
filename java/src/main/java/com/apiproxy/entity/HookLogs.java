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
@Table(name = "hook_logs")
public class HookLogs {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hookId;
    private String hookName;
    private String eventName;
    private String triggerUid;
    private String triggerName;
    private Integer matched;
    private String conditionText;
    private String result;
    private String error;
    private Integer durationMs;
    private LocalDateTime createdAt;
}

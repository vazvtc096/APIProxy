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
@Table(name = "scheduled_tasks")
public class ScheduledTasks {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String taskName;
    private String behavior;
    private String scope;
    private String params;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private String frequency;
    private String cronExpression;
    private LocalDateTime lastRunAt;
    private LocalDateTime nextRunAt;
    private Integer isEnabled;
    private String createdBy;
    private LocalDateTime createdAt;
    private Integer runCount;
    private String status;
}

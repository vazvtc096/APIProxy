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
@Table(name = "bastion_audit")
public class BastionAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sessionId;
    private String nodeId;
    private String operator;
    private String target;
    private String command;
    private String args;
    private Integer resultOk;
    private String output;
    private String risk;
    private LocalDateTime createdAt;
}

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
@Table(name = "bastion_approvals")
public class BastionApprovals {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ticketId;
    private String operator;
    private String command;
    private String args;
    private String status;
    private String reviewer;
    private String note;
    private LocalDateTime createdAt;
    private LocalDateTime decidedAt;
}

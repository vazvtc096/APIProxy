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
@Table(name = "web_access_log")
public class WebAccessLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String userUid;
    private String userName;
    private String clientIp;
    private String method;
    private String path;
    private String query;
    private String category;
    private String action;
    private Integer status;
    private Integer bytes;
    private LocalDateTime createdAt;
}

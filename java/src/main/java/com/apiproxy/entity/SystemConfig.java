package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "system_config")
public class SystemConfig {

    @Id
    @Column(name = "key")
    private String key;

    @Column(name = "value")
    private String value;

    private LocalDateTime updatedAt;
}

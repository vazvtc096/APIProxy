package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "config_kv")
public class ConfigKv {

    @Id
    @Column(name = "key")
    private String key;

    @Column(name = "value")
    private String value;
}

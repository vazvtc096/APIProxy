package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "upstreams")
public class Upstream {

    @Id
    @Column(name = "name")
    private String name;

    @Column(name = "base_url")
    private String baseUrl;

    @Column(name = "api_key")
    private String apiKey;

    @Column(name = "priority")
    private Integer priority;

    @Column(name = "enabled")
    private Integer enabled;

    @Column(name = "disabled_models")
    private String disabledModels;
}

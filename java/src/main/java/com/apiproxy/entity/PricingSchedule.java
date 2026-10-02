package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "pricing_schedules")
public class PricingSchedule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "model")
    private String model;

    @Column(name = "\"start\"")
    private String start;

    @Column(name = "\"end\"")
    private String end;

    @Column(name = "input")
    private Double input;

    @Column(name = "output")
    private Double output;

    @Column(name = "enabled")
    private Integer enabled;
}

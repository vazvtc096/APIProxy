package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "model_prices")
public class ModelPrice {

    @Id
    @Column(name = "model")
    private String model;

    @Column(name = "input")
    private Double input;

    @Column(name = "output")
    private Double output;

    @Column(name = "priced")
    private Integer priced;
}

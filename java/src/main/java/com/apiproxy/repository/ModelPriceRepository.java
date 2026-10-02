package com.apiproxy.repository;

import com.apiproxy.entity.ModelPrice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ModelPriceRepository extends JpaRepository<ModelPrice, String> {

    /** 查询管理员定价（priced=1 表示已定价） */
    Optional<ModelPrice> findByModelAndPriced(String model, Integer priced);
}

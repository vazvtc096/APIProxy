package com.apiproxy.repository;

import com.apiproxy.entity.RconConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RconConfigRepository extends JpaRepository<RconConfig, Long> {

    List<RconConfig> findAllByOrderByIdAsc();
}

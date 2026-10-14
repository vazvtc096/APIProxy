package com.apiproxy.repository;

import com.apiproxy.entity.DebugConsoleConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DebugConsoleConfigRepository extends JpaRepository<DebugConsoleConfig, Long> {

    List<DebugConsoleConfig> findAllByOrderByIdAsc();
}

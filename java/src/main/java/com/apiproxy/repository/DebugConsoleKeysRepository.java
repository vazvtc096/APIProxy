package com.apiproxy.repository;

import com.apiproxy.entity.DebugConsoleKeys;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DebugConsoleKeysRepository extends JpaRepository<DebugConsoleKeys, Long> {

    List<DebugConsoleKeys> findAllByOrderByCreatedAtDesc();

    Optional<DebugConsoleKeys> findByKeyHash(String keyHash);

    Optional<DebugConsoleKeys> findByKeyHashAndIsActive(String keyHash, Integer isActive);
}

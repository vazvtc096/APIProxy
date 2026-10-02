package com.apiproxy.repository;

import com.apiproxy.entity.RconKeys;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RconKeysRepository extends JpaRepository<RconKeys, Long> {

    List<RconKeys> findAllByOrderByCreatedAtDesc();

    Optional<RconKeys> findByKeyHash(String keyHash);

    Optional<RconKeys> findByKeyHashAndIsActive(String keyHash, Integer isActive);
}

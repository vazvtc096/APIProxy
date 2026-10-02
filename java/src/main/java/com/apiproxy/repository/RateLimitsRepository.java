package com.apiproxy.repository;

import com.apiproxy.entity.RateLimits;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RateLimitsRepository extends JpaRepository<RateLimits, Long> {
}

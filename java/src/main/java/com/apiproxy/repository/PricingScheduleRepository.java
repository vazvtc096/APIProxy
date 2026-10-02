package com.apiproxy.repository;

import com.apiproxy.entity.PricingSchedule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PricingScheduleRepository extends JpaRepository<PricingSchedule, Integer> {
}

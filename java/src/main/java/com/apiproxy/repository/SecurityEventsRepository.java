package com.apiproxy.repository;

import com.apiproxy.entity.SecurityEvents;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityEventsRepository extends JpaRepository<SecurityEvents, Long> {
}

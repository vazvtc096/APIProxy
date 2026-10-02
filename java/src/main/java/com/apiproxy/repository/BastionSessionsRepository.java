package com.apiproxy.repository;

import com.apiproxy.entity.BastionSessions;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BastionSessionsRepository extends JpaRepository<BastionSessions, Long> {
}

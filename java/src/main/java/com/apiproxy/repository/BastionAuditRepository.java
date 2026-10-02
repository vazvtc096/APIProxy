package com.apiproxy.repository;

import com.apiproxy.entity.BastionAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BastionAuditRepository extends JpaRepository<BastionAudit, Long> {
}

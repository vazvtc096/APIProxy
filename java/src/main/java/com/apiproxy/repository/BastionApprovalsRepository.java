package com.apiproxy.repository;

import com.apiproxy.entity.BastionApprovals;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BastionApprovalsRepository extends JpaRepository<BastionApprovals, Long> {
}

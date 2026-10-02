package com.apiproxy.repository;

import com.apiproxy.entity.HookLogs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HookLogsRepository extends JpaRepository<HookLogs, Long> {
}

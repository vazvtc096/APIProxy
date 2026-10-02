package com.apiproxy.repository;

import com.apiproxy.entity.TaskExecutionLogs;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface TaskExecutionLogsRepository extends JpaRepository<TaskExecutionLogs, Long> {
}

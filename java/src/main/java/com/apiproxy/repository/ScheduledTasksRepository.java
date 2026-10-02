package com.apiproxy.repository;

import com.apiproxy.entity.ScheduledTasks;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ScheduledTasksRepository extends JpaRepository<ScheduledTasks, Long> {
}

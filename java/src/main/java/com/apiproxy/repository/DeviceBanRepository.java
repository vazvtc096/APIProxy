package com.apiproxy.repository;

import com.apiproxy.entity.DeviceBan;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DeviceBanRepository extends JpaRepository<DeviceBan, Long> {
}

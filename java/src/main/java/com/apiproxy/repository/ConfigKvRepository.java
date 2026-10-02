package com.apiproxy.repository;

import com.apiproxy.entity.ConfigKv;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ConfigKvRepository extends JpaRepository<ConfigKv, String> {
}

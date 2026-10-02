package com.apiproxy.repository;

import com.apiproxy.entity.Hooks;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface HooksRepository extends JpaRepository<Hooks, Long> {
}

package com.apiproxy.repository;

import com.apiproxy.entity.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IpBlacklistRepository extends JpaRepository<IpBlacklist, Long> {

    Optional<IpBlacklist> findByIp(String ip);
}

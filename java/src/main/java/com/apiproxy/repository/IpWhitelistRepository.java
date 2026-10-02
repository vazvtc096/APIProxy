package com.apiproxy.repository;

import com.apiproxy.entity.IpWhitelist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IpWhitelistRepository extends JpaRepository<IpWhitelist, Long> {
}

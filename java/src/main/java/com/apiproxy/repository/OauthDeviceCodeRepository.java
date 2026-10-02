package com.apiproxy.repository;

import com.apiproxy.entity.OauthDeviceCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthDeviceCodeRepository extends JpaRepository<OauthDeviceCode, Integer> {

    Optional<OauthDeviceCode> findByDeviceCode(String deviceCode);

    Optional<OauthDeviceCode> findByUserCode(String userCode);
}

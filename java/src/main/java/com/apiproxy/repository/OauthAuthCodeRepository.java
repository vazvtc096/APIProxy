package com.apiproxy.repository;

import com.apiproxy.entity.OauthAuthCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthAuthCodeRepository extends JpaRepository<OauthAuthCode, Integer> {

    Optional<OauthAuthCode> findByCode(String code);
}

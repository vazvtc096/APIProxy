package com.apiproxy.repository;

import com.apiproxy.entity.OauthToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthTokenRepository extends JpaRepository<OauthToken, Integer> {

    Optional<OauthToken> findByAccessJti(String accessJti);

    Optional<OauthToken> findByRefreshToken(String refreshToken);
}

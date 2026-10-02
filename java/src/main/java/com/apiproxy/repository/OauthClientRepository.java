package com.apiproxy.repository;

import com.apiproxy.entity.OauthClient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OauthClientRepository extends JpaRepository<OauthClient, Integer> {

    Optional<OauthClient> findByClientId(String clientId);
}

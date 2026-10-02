package com.apiproxy.repository;

import com.apiproxy.entity.Apikey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ApikeyRepository extends JpaRepository<Apikey, Integer> {

    Optional<Apikey> findByApikeyHash(String apikeyHash);

    List<Apikey> findByOwnerName(String ownerName);

    /** 删除指定用户名下的指定哈希的 API Key */
    @Modifying
    @Query("DELETE FROM Apikey a WHERE a.apikeyHash = :hash AND a.ownerName = :owner")
    int deleteByApikeyHashAndOwnerName(@Param("hash") String apikeyHash, @Param("owner") String ownerName);

    /** 更新最后使用时间（API Key 验证时调用） */
    @Modifying
    @Query("UPDATE Apikey a SET a.lastUsedAt = :ts WHERE a.apikeyHash = :hash")
    int updateLastUsedAt(@Param("hash") String apikeyHash, @Param("ts") LocalDateTime lastUsedAt);
}

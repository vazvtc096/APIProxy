package com.apiproxy.repository;

import com.apiproxy.entity.Session;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<Session, Integer> {

    Optional<Session> findBySessionId(String sessionId);

    List<Session> findByUserName(String userName);

    long countByUserName(String userName);

    /** 最旧的活跃会话（用于踢出多设备登录的旧会话） */
    Optional<Session> findFirstByUserNameOrderByCreatedAtAsc(String userName);

    /** 删除指定 session_id 的会话（登出时调用） */
    @Modifying
    void deleteBySessionId(String sessionId);

    /** 清理过期会话 */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.expiresAt < :now")
    int deleteExpiredBefore(@Param("now") LocalDateTime now);

    /** 删除某用户全部会话（封禁/注销时调用） */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.userName = :userName")
    int deleteByUserName(@Param("userName") String userName);
}

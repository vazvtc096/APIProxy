package com.apiproxy.repository;

import com.apiproxy.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

    Optional<User> findByUserName(String userName);

    Optional<User> findByUid(String uid);

    Optional<User> findByEmail(String email);

    /** 原子扣减余额（供 BillingService 预扣/强制扣费调用） */
    @Modifying
    @Query("UPDATE User u SET u.balence = u.balence - :amount WHERE u.userName = :username")
    int deductBalance(@Param("username") String username, @Param("amount") double amount);

    /** 原子增加余额（供 BillingService 退还调用） */
    @Modifying
    @Query("UPDATE User u SET u.balence = u.balence + :amount WHERE u.userName = :username")
    int addBalance(@Param("username") String username, @Param("amount") double amount);

    /** 读取 allow_overdraft 列（实体未映射，用原生 SQL） */
    @Query(value = "SELECT allow_overdraft FROM users WHERE user_name = :username", nativeQuery = true)
    Integer findAllowOverdraftByUserName(@Param("username") String username);
}

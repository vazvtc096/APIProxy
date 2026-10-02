package com.apiproxy.repository;

import com.apiproxy.entity.BalenceTransaction;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface BalenceTransactionRepository extends JpaRepository<BalenceTransaction, Integer> {

    /** 用户余额变动记录（按类型过滤，分页） */
    Page<BalenceTransaction> findByUserUidAndType(String userUid, String type, Pageable pageable);

    Page<BalenceTransaction> findByUserUid(String userUid, Pageable pageable);

    /** 注销账号时级联删除余额流水 */
    @Modifying
    @Query("DELETE FROM BalenceTransaction b WHERE b.userUid = :uid")
    int deleteByUserUid(@Param("uid") String uid);
}

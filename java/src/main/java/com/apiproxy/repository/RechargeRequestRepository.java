package com.apiproxy.repository;

import com.apiproxy.entity.RechargeRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RechargeRequestRepository extends JpaRepository<RechargeRequest, Integer> {

    /** 查询用户充值请求（按状态过滤，分页） */
    Page<RechargeRequest> findByUserUidAndStatus(String userUid, String status, Pageable pageable);

    Page<RechargeRequest> findByUserUid(String userUid, Pageable pageable);

    /** 注销账号时级联删除充值请求 */
    @Modifying
    @Query("DELETE FROM RechargeRequest r WHERE r.userUid = :uid")
    int deleteByUserUid(@Param("uid") String uid);

    /** 管理员待处理列表 */
    List<RechargeRequest> findByStatusOrderByCreatedAtDesc(String status);
}

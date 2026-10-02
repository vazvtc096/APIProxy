package com.apiproxy.repository;

import com.apiproxy.entity.Friend;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FriendRepository extends JpaRepository<Friend, Integer> {

    List<Friend> findByUserUidAndStatus(String userUid, String status);

    /** 注销账号时级联删除好友关系（避免孤儿数据，硬约束） */
    @Modifying
    @Query("DELETE FROM Friend f WHERE f.userUid = :uid OR f.friendUid = :uid")
    int deleteAllByUserUidOrFriendUid(@Param("uid") String uid);
}

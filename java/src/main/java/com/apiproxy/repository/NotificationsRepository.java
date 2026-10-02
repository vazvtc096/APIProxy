package com.apiproxy.repository;

import com.apiproxy.entity.Notifications;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NotificationsRepository extends JpaRepository<Notifications, String> {

    /** 未读通知数（对齐 Python notifications.unread_count：COALESCE(is_read,0)=0） */
    @Query("SELECT COUNT(n) FROM Notifications n WHERE n.userUid = :uid AND COALESCE(n.isRead, 0) = 0")
    long countUnreadByUid(@Param("uid") String uid);

    /** 分页取通知（按 created_at 倒序，对齐 Python get_notifications 的 LIMIT） */
    @Query(value = "SELECT * FROM notifications WHERE user_uid = :uid ORDER BY created_at DESC LIMIT :limit OFFSET :offset",
            nativeQuery = true)
    List<Notifications> findPageByUid(@Param("uid") String uid,
                                      @Param("limit") int limit,
                                      @Param("offset") int offset);

    /** 分页取未读通知 */
    @Query(value = "SELECT * FROM notifications WHERE user_uid = :uid AND COALESCE(is_read, 0) = 0 "
            + "ORDER BY created_at DESC LIMIT :limit OFFSET :offset", nativeQuery = true)
    List<Notifications> findPageByUidUnread(@Param("uid") String uid,
                                            @Param("limit") int limit,
                                            @Param("offset") int offset);

    /** 标记单条已读（需属于该用户） */
    @Modifying
    @Query("UPDATE Notifications n SET n.isRead = 1 WHERE n.id = :id AND n.userUid = :uid")
    int markReadByIdAndUid(@Param("id") String id, @Param("uid") String uid);

    /** 标记该用户全部已读 */
    @Modifying
    @Query("UPDATE Notifications n SET n.isRead = 1 WHERE n.userUid = :uid")
    int markAllReadByUid(@Param("uid") String uid);
}

package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 帖子收藏实体，对应 post_favorites 表。
 */
@Data
@Entity
@Table(name = "post_favorites", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"user_uid", "post_id"})
})
public class PostFavorite {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "user_uid")
    private String userUid;

    @Column(name = "post_id")
    private String postId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

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
 * 帖子收藏实体（uid 口径），对应 post_collections 表。
 */
@Data
@Entity
@Table(name = "post_collections", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"uid", "post_id"})
})
public class PostCollection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "uid")
    private String uid;

    @Column(name = "post_id")
    private Integer postId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

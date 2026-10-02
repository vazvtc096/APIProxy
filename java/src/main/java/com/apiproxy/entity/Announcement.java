package com.apiproxy.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 管理员公告实体，对应 announcements 表。
 */
@Data
@Entity
@Table(name = "announcements")
public class Announcement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "announcement_id", unique = true)
    private String announcementId;

    @Column(name = "title")
    private String title;

    @Column(name = "content")
    private String content;

    @Column(name = "level")
    private String level;

    @Column(name = "target")
    private String target;

    @Column(name = "target_detail")
    private String targetDetail;

    @Column(name = "sender_uid")
    private String senderUid;

    @Column(name = "sender_name")
    private String senderName;

    @Column(name = "recipients")
    private Integer recipients;

    @Column(name = "pinned")
    private Integer pinned;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

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
 * 聊天消息实体，对应 chat_messages 表（含 is_read、announcement_id 增补字段）。
 */
@Data
@Entity
@Table(name = "chat_messages")
public class ChatMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Integer id;

    @Column(name = "message_id", unique = true)
    private String messageId;

    @Column(name = "from_uid")
    private String fromUid;

    @Column(name = "from_name")
    private String fromName;

    @Column(name = "to_uid")
    private String toUid;

    @Column(name = "to_name")
    private String toName;

    @Column(name = "content")
    private String content;

    @Column(name = "type")
    private String type;

    @Column(name = "amount")
    private Double amount;

    @Column(name = "status")
    private String status;

    @Column(name = "is_read")
    private Integer isRead;

    @Column(name = "announcement_id")
    private String announcementId;

    @Column(name = "read_at")
    private LocalDateTime readAt;

    @Column(name = "claimed_at")
    private LocalDateTime claimedAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;
}

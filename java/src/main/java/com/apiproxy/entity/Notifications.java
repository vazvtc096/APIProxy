package com.apiproxy.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "notifications")
public class Notifications {

    @Id
    private String id;

    private String userUid;
    private String title;
    private String body;
    private String level;
    private String link;
    private String announcementId;
    private Integer isRead;
    private String createdAt;
}

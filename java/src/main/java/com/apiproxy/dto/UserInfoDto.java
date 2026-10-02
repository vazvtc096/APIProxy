package com.apiproxy.dto;

import lombok.Data;

import java.util.List;

/**
 * 用户信息 DTO。
 *
 * 对应 Python user.py 的 /userinfo 返回结构。
 */
@Data
public class UserInfoDto {

    private String username;
    private String uid;
    private Double balence;
    private Boolean isAdmin;
    private Boolean isBanned;
    private String banReason;
    private String email;
    private Integer loginCount;
    private Double totalSpent;
    private String createdAt;
    private List<String> apikeys;
}

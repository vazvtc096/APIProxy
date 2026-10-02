package com.apiproxy.dto;

import lombok.Data;

/**
 * 用户设置 DTO。
 *
 * 对应 Python user.py 的 /api/user/settings 更新接口。
 */
@Data
public class SettingsDto {

    private String email;
    private Integer maxSessions;
    private Integer allowOverdraft;
    private Double maxOverdraft;
}

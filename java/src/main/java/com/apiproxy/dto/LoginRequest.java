package com.apiproxy.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * 登录请求 DTO。
 *
 * 注意：实际登录由 Spring Security 表单登录处理（SecurityConfig），
 * 此 DTO 供 API 化登录场景或测试使用。
 */
@Data
public class LoginRequest {

    @NotBlank(message = "Username required")
    private String username;

    @NotBlank(message = "Password required")
    private String password;
}

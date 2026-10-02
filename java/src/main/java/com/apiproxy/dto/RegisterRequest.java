package com.apiproxy.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * 注册请求 DTO。
 *
 * 对应 Python auth.py /register 接口的请求体。
 */
@Data
public class RegisterRequest {

    @NotBlank(message = "Username required")
    @Size(max = 32, message = "Username too long (max 32 chars)")
    private String username;

    @NotBlank(message = "Password required")
    @Size(min = 8, message = "Password too short (min 8 chars)")
    private String password;

    private String email;

    private String code;

    private String captchaToken;

    private String captchaX;
}

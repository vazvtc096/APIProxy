package com.apiproxy.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * RCON 远程服务器配置（Source RCON 协议）。
 *
 * 每条记录对应一台可连接的远程游戏/服务器（host:port + 认证密码），
 * 由管理员通过 /api/rcon/configs 维护，用于执行远程控制台命令。
 */
@Data
@Entity
@Table(name = "rcon_config")
public class RconConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** 配置名称 */
    private String name;

    /** 服务器主机名 / IP */
    private String host;

    /** 服务器 RCON 端口 */
    private Integer port;

    /** RCON 认证密码 */
    private String password;

    /** 是否启用：1=启用，0=禁用 */
    private Integer enabled;

    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;
}

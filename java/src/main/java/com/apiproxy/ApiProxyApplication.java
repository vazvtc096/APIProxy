package com.apiproxy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * APIProxy Java 版入口。
 *
 * 对应 Python __main__.py：启动 Quart app + 调度器 + 集群发现。
 * Spring Boot 自动配置覆盖数据源/JPA/Security/Thymeleaf。
 */
@SpringBootApplication
@EnableScheduling
public class ApiProxyApplication {

    public static void main(String[] args) {
        SpringApplication.run(ApiProxyApplication.class, args);
    }
}

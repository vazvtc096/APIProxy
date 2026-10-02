package com.apiproxy.config;

import com.apiproxy.security.CompatiblePasswordEncoder;
import com.apiproxy.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
 * Spring Security 配置。
 *
 * 对应 Python middleware/security_middleware.py 的认证/会话/CSRF 部分。
 * - 表单登录（/login + /register 为公开页）
 * - bcrypt 密码哈希（与 Python bcrypt 兼容，rounds=12）
 * - CSRF 防护（Cookie 存储，前端 JS 可读取）
 * - 会话超时 24h（application.yml 已配）
 * - 路径级授权：OpenAI API 端点用 API Key 认证，其余按角色
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(CustomUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder(CompatiblePasswordEncoder encoder) {
        // 兼容 Python 现有哈希：$scrypt$ / $2b$ / pbkdf2: 三种格式都可验证
        // 新密码用 BCrypt(12)，与 Python bcrypt.checkpw 互通
        return encoder;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .userDetailsService(userDetailsService)
            // 公开路径
            .authorizeHttpRequests(auth -> auth
                // 静态资源 + 页面
                .requestMatchers("/", "/login", "/register", "/forgot-password",
                                 "/css/**", "/js/**", "/img/**", "/favicon.ico").permitAll()
                // OpenAI 兼容 API（API Key 认证，不走 session）
                .requestMatchers("/v1/**", "/api/models", "/api/chat/**").permitAll()
                // 健康检查
                .requestMatchers("/health", "/ready", "/api/health/**").permitAll()
                // OAuth2 端点
                .requestMatchers("/oauth/**", "/api/oauth/**").permitAll()
                // RCON 登录页
                .requestMatchers("/rcon/login", "/rcon/login").permitAll()
                // 公开 API
                .requestMatchers("/api/email/**", "/api/captcha/**").permitAll()
                // 管理员接口
                .requestMatchers("/api/admin/**", "/admin/**").hasRole("ADMIN")
                // RCON 接口
                .requestMatchers("/rcon/**", "/api/rcon/**").hasRole("ADMIN")
                // 其余需登录
                .anyRequest().authenticated()
            )
            // 表单登录
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=1")
                .permitAll()
            )
            // 登出
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=1")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID", "XSRF-TOKEN")
                .permitAll()
            )
            // CSRF：Cookie 存储，前端 JS 可读取 XSRF-TOKEN
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // OpenAI API 端点免 CSRF（API Key 认证）
                .ignoringRequestMatchers("/v1/**", "/api/chat/**", "/api/models",
                                          // OAuth2 端点整体免 CSRF（对齐 Python：/oauth/ 前缀豁免，
                                          // 机到机调用靠 client secret / Authorization 头鉴权）
                                          "/oauth/**",
                                          "/api/health/**",
                                          "/api/rcon/**")
            )
            // 会话管理
            .sessionManagement(session -> session
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)  // 踢掉旧会话
            );

        return http.build();
    }
}

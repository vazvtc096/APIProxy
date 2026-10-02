package com.apiproxy.security;

import com.apiproxy.entity.User;
import com.apiproxy.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * 从 DB 加载用户供 Spring Security 认证。
 *
 * 对应 Python core_auth.py 的登录校验逻辑：
 * 1. 根据 user_name 查 users 表
 * 2. 校验 bcrypt 密码哈希
 * 3. 检查 is_banned（Spring Security 通过 isAccountNonLocked 实现）
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("用户不存在: " + username));

        if (user.getIsBanned() != null && user.getIsBanned() == 1) {
            // 对应 Python：被封禁用户无法登录
            throw new UsernameNotFoundException("账号已被封禁: " + user.getBanReason());
        }

        return new CustomUserDetails(user);
    }
}

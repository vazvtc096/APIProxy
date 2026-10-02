package com.apiproxy.security;

import com.apiproxy.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

/**
 * 包装 User 实体的 UserDetails 实现。
 *
 * 对应 Python session['user'] = username（字符串）的语义，
 * Spring Security 需要 UserDetails 对象来封装认证信息。
 */
public class CustomUserDetails implements UserDetails {

    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (user.getIsAdmin() != null && user.getIsAdmin() == 1) {
            return Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        return user.getUserPassword();
    }

    @Override
    public String getUsername() {
        // session['user'] 存的是 user_name 字符串，与 Python 版一致
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // is_banned=1 表示被封禁
        return user.getIsBanned() == null || user.getIsBanned() == 0;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    /** 获取关联的 User 实体（供 Controller/Service 使用 uid 等字段） */
    public User getUser() {
        return user;
    }

    /** 获取用户 UID（对外展示用，与 Python session['uid'] 对应） */
    public String getUid() {
        return user.getUid();
    }
}

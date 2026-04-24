package com.crowdsource.userservice.security;

import com.crowdsource.userservice.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private final Long userId;
    private final String username;  // EMAIL (login identifier)
    private final String password;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    // From User entity (email = username)
    public CustomUserDetails(User user) {
        this.userId = user.getId();
        this.username = user.getEmail();  // EMAIL as username
        this.password = user.getPassword();
        this.enabled = user.isEnabled();
        this.authorities = user.getAuthorities();
    }

    // From JWT claims
    public CustomUserDetails(Long userId, String email, String password,
                             List<String> authorityStrings, boolean enabled) {
        this.userId = userId;
        this.username = email;  // Email
        this.password = password;
        this.enabled = enabled;
        this.authorities = authorityStrings.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

}
package com.crowdsource.userservice.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * Usable from SpEL: {@code @PreAuthorize("@securityService.isOwner(authentication, #id)")}.
 * The principal is the user id (String) provided by the gateway headers, not a UserDetails object.
 */
@Component("securityService")
public class SecurityService {

    public boolean isOwner(Authentication authentication, Long targetUserId) {
        if (authentication == null || !authentication.isAuthenticated() || targetUserId == null) {
            return false;
        }
        return String.valueOf(targetUserId).equals(authentication.getName());
    }
}

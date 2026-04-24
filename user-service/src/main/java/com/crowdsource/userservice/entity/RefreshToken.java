package com.crowdsource.userservice.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.LocalDateTime;

import static com.google.common.hash.Hashing.sha256;

@Data
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(columnList = "userId"),
        @Index(columnList = "tokenHash"),
        @Index(columnList = "expiresAt")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;  // SHA256(opaque)

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public static RefreshToken create(String rawToken, Long userId, Duration ttl) {
        RefreshToken token = new RefreshToken();
        token.tokenHash = RefreshToken.hash(rawToken);
        token.userId = userId;
        token.expiresAt = LocalDateTime.now().plus(ttl);
        return token;
    }

    public static String hash(String rawToken) {
        return sha256()
                .hashString(rawToken, StandardCharsets.UTF_8)
                .toString();  // 64-char hex
    }

    public boolean isValid() {
        return !revoked && expiresAt.isAfter(LocalDateTime.now());
    }
}

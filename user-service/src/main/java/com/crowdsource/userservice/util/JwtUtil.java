package com.crowdsource.userservice.util;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.security.CustomUserDetails;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Slf4j
@Component
public class JwtUtil {

    private static final long ACCESS_TOKEN_EXPIRY = 15 * 60 * 1000; // 15 mins
    private static final long REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days
    // Define a constant for the Key ID.
    // This MUST match the one you exposed in your JwksController.
    private static final String KEY_ID = "auth-key-1";

    // ... existing fields and constructor ...
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Autowired
    public JwtUtil(PemKeyLoader pemKeyLoader) {
        this.privateKey = pemKeyLoader.getPrivateKey();
        this.publicKey = pemKeyLoader.getPublicKey();
        log.info("JwtUtil initialized with ECDSA keys (ES256)");
    }

    public String generateAccessToken(CustomUserDetails userDetails) {
        return Jwts.builder()
                .header()
                .keyId(KEY_ID) // <--- CRITICAL: Adds 'kid' to the JWT header
                .and()
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getUserId())
                .claim("username", userDetails.getUsername())
                .claim("roles", extractRoles(userDetails.getAuthorities()))
                .claim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).toList())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY))
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();
    }

    public String generateRefreshToken(CustomUserDetails userDetails) {
        return Jwts.builder()
                .header()
                .keyId(KEY_ID) // <--- CRITICAL: Adds 'kid' to the JWT header
                .and()
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getUserId())
                .claim("username", userDetails.getUsername())
                .claim("roles", extractRoles(userDetails.getAuthorities()))
                .claim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).toList())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRY))
                .signWith(privateKey, SignatureAlgorithm.ES256)
                .compact();
    }

    // Extract roles with "ROLE_" prefix
    public List<String> extractRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(auth -> auth.startsWith("ROLE_"))
                .map(auth -> auth.substring(5))  // "ROLE_ADMIN" → "ADMIN"
                .toList();
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)  // ← CHANGED: Now verifying with public key
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (Exception e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public AuthResponse buildAuthResponse(String accessToken, String refreshToken) {
        return AuthResponse.builder()
                .accessToken(accessToken)
                .tokenType("Bearer")
                .expiresIn(ACCESS_TOKEN_EXPIRY / 1000)
                .refreshToken(refreshToken)
                .refreshExpiresIn(REFRESH_TOKEN_EXPIRY / 1000)
                .build();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.debug("Invalid token: {}", e.getMessage());
            return false;
        }
    }

    public boolean validateToken(String token, CustomUserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
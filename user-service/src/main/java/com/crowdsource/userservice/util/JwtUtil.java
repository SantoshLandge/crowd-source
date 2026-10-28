package com.crowdsource.userservice.util;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.security.CustomUserDetails;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;

@Slf4j
@Component
public class JwtUtil {

    private static final long ACCESS_TOKEN_EXPIRY = 15 * 60 * 1000; // 15 mins
    private static final long REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7 days
    // Define a constant for the Key ID.
    // This MUST match the one in JwksController.
    private static final String KEY_ID = "auth-key-1";
    private final PrivateKey privateKey;

    @Autowired
    public JwtUtil(PemKeyLoader pemKeyLoader) {
        this.privateKey = pemKeyLoader.getPrivateKey();
        log.debug("JwtUtil initialized with ECDSA keys (ES256)");
    }

    public String generateAccessToken(CustomUserDetails userDetails) {
        return Jwts.builder()
                .header()
                .keyId(KEY_ID) // Adds 'kid' to the JWT header
                .and()
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getUserId())
                .claim("username", userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).toList())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY))
                .signWith(privateKey, Jwts.SIG.ES256)
                .compact();
    }

    // Centralized Cookie & Response Generator
    public ResponseEntity<?> createAuthResponseWithCookies(String accessToken, String refreshToken, AuthResponse userInfo, String message) {

        ResponseCookie accessCookie = generateCookie("access_token", accessToken, ACCESS_TOKEN_EXPIRY, "/");
        // TODO .path("/api/auth/refresh") // The browser will ONLY send this cookie to this specific endpoint
        ResponseCookie refreshCookie = generateCookie("refresh_token", refreshToken, REFRESH_TOKEN_EXPIRY, "/");

        Map<String, Object> responseBody = Map.of(
                "message", message,
                "user", userInfo
        );

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(responseBody);
    }

    private ResponseCookie generateCookie(String name, String value, long maxAgeSecs, String path) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(false) // Toggle to true in production environment
                .path(path)
                .maxAge(maxAgeSecs / 1000)
                .sameSite("Lax")
                .build();
    }

}
package com.crowdsource.userservice.util;

import com.crowdsource.userservice.dto.AuthResponse;
import com.crowdsource.userservice.security.CustomUserDetails;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.interfaces.ECPrivateKey;
import java.time.Duration;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
public class JwtUtil {

    public static final String ACCESS_COOKIE = "access_token";
    public static final String REFRESH_COOKIE = "refresh_token";

    public static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);
    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);

    /** Key id published in the JWKS endpoint (JwksController) and set in every token header. */
    public static final String KEY_ID = "auth-key-1";

    private final ECPrivateKey privateKey;
    private final String issuer;
    private final boolean cookieSecure;
    private final String sameSite;
    private final String refreshCookiePath;

    @Autowired
    public JwtUtil(PemKeyLoader pemKeyLoader,
                   @Value("${app.security.jwt.issuer:crowdsource-user-service}") String issuer,
                   @Value("${app.security.cookie-secure:false}") boolean cookieSecure,
                   @Value("${app.security.cookie-same-site:Lax}") String sameSite,
                   @Value("${app.security.refresh-cookie-path:/api/auth/v1}") String refreshCookiePath) {
        this.privateKey = (ECPrivateKey) pemKeyLoader.getPrivateKey();   // PemKeyLoader guarantees an EC P-256 key
        this.issuer = issuer;
        this.cookieSecure = cookieSecure;
        this.sameSite = sameSite;
        this.refreshCookiePath = refreshCookiePath;
        log.debug("JwtUtil initialized (ES256, issuer={}, secureCookies={})", issuer, cookieSecure);
    }

    /**
     * ES256-signed access token. Signed with Nimbus (already on the classpath for the JWKS endpoint), which also
     * keeps this service free of a second JSON stack (JJWT needed Jackson 2, Boot 4 uses Jackson 3).
     */
    public String generateAccessToken(CustomUserDetails userDetails) {
        long now = System.currentTimeMillis();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .jwtID(UUID.randomUUID().toString())
                .subject(userDetails.getUsername())
                .claim("userId", userDetails.getId().toString())          // UUID as string
                .claim("username", userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).toList())
                .issueTime(new Date(now))
                .expirationTime(new Date(now + ACCESS_TOKEN_TTL.toMillis()))
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(KEY_ID)
                .type(JOSEObjectType.JWT)
                .build();
        try {
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(privateKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Unable to sign access token", e);
        }
    }

    /** Sets the access + refresh cookies (HttpOnly) and returns the profile metadata as JSON body. */
    public ResponseEntity<?> createAuthResponseWithCookies(HttpStatus status, String accessToken, String refreshToken,
                                                           AuthResponse userInfo, String message) {
        ResponseCookie accessCookie = cookie(ACCESS_COOKIE, accessToken, ACCESS_TOKEN_TTL, "/");
        // The refresh cookie is only sent by the browser to the auth endpoints (refresh / logout / logout-all)
        ResponseCookie refreshCookie = cookie(REFRESH_COOKIE, refreshToken, REFRESH_TOKEN_TTL, refreshCookiePath);

        Map<String, Object> body = Map.of("message", message, "user", userInfo);

        return ResponseEntity.status(status)
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(body);
    }

    /** Expires both cookies in the browser (same name/path/attributes as when they were set). */
    public ResponseEntity<?> createLogoutResponse(String message) {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie(ACCESS_COOKIE, "", Duration.ZERO, "/").toString())
                .header(HttpHeaders.SET_COOKIE, cookie(REFRESH_COOKIE, "", Duration.ZERO, refreshCookiePath).toString())
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of("message", message));
    }

    private ResponseCookie cookie(String name, String value, Duration maxAge, String path) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookieSecure)        // set app.security.cookie-secure=true behind HTTPS (prod profile does)
                .path(path)
                .maxAge(maxAge)
                .sameSite(sameSite)
                .build();
    }
}

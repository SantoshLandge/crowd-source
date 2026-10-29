package com.crowdsource.security.shared.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration for the shared gateway-trust security.
 *
 * <pre>
 * security:
 *   shared:
 *     gateway-secret: ${GATEWAY_SHARED_SECRET}   # must match the api-gateway (min 32 chars)
 *     max-clock-skew: 60s
 *     public-paths:                              # extra paths reachable without authentication
 *       - /auth/v1/login
 * </pre>
 */
@ConfigurationProperties(prefix = "security.shared")
public class SharedSecurityProperties {

    /** Shared HMAC secret used to verify the identity headers forwarded by the gateway. */
    private String gatewaySecret;

    /** Maximum accepted age (and clock drift) of a signed identity header set. */
    private Duration maxClockSkew = Duration.ofSeconds(60);

    /** Additional ant-style paths that do not require authentication. */
    private List<String> publicPaths = new ArrayList<>();

    public String getGatewaySecret() {
        return gatewaySecret;
    }

    public void setGatewaySecret(String gatewaySecret) {
        this.gatewaySecret = gatewaySecret;
    }

    public Duration getMaxClockSkew() {
        return maxClockSkew;
    }

    public void setMaxClockSkew(Duration maxClockSkew) {
        this.maxClockSkew = maxClockSkew;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }
}

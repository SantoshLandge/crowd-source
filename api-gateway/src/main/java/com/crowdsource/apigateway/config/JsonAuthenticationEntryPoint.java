package com.crowdsource.apigateway.config;

import com.crowdsource.apigateway.dto.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

// for missing/invalid authentication
@Component
public class JsonAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {
    private final ObjectMapper objectMapper;

    public JsonAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String message = "Authentication token is missing, invalid, or expired";

        // Check for JWT expiration
        if (ex.getCause() instanceof org.springframework.security.oauth2.jwt.JwtValidationException) {
            message = "JWT token has expired";
        }
        // Check for invalid bearer token - InvalidBearerTokenException
        else if (ex instanceof org.springframework.security.oauth2.server.resource.InvalidBearerTokenException) {
            message = "Invalid or expired JWT token";
        }

        return write(exchange, status, message);
    }

    private Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String message) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        ApiError body = new ApiError(
                Instant.now(),
                status.value(),
                status.getReasonPhrase(),
                message,
                exchange.getRequest().getPath().value()
        );
        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return exchange.getResponse().setComplete();
        }
    }
}
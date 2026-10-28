package com.crowdsource.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                            JsonAuthenticationEntryPoint authenticationEntryPoint,
                                                            JsonAccessDeniedHandler accessDeniedHandler) {

        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        // Public endpoints
                        .pathMatchers(
                                "/api/auth/v1/signup",
                                "/api/auth/v1/login",
                                "/api/auth/v1/refresh",
                                "/api/auth/v1/logout",
                                "/api/auth/v1/logout-all"
                        ).permitAll()
                        // RBAC checks inside SecurityConfig only
                        .pathMatchers("/user/api/admin/**", "/actuator/**").hasRole("ADMIN")
                        .pathMatchers("/report/api/**").hasAnyRole("ADMIN", "ORGANIZER")
                        .anyExchange().authenticated()
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .bearerTokenConverter(cookieTokenConverter) // Sets cookie resolver
                        .jwt(jwt -> jwt
                                .jwtDecoder(reactiveJwtDecoder())
                                .jwtAuthenticationConverter(jwtAuthenticationConverter()) // Binds roles mapping
                        )
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                .build();
    }


    // Custom reactive converter to extract the JWT from the cookie directly
    ServerAuthenticationConverter cookieTokenConverter = exchange -> {
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst("access_token");
        return cookie != null
                ? Mono.just(new BearerTokenAuthenticationToken(cookie.getValue()))
                : Mono.empty();
    };

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
                .jwsAlgorithm(SignatureAlgorithm.ES256)
                .build();
    }

    @Bean
    public ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // Looks for "authorities" claim inside the JWT
        authoritiesConverter.setAuthoritiesClaimName("authorities");

        // Maps "ADMIN" -> "ROLE_ADMIN" for Spring's .hasRole() to function
//        authoritiesConverter.setAuthorityPrefix("ROLE_");

        // Clear the default "SCOPE_" prefix so roles stay exactly as they are in the token
        authoritiesConverter.setAuthorityPrefix("");

        converter.setJwtGrantedAuthoritiesConverter(new ReactiveJwtGrantedAuthoritiesConverterAdapter(authoritiesConverter));
        return converter;
    }
}

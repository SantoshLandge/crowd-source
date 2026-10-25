package com.crowdsource.userservice.config;

import com.crowdsource.security.shared.filter.SharedGatewayHeaderFilter;
import com.crowdsource.security.shared.handler.SharedSecurityExceptionHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@EnableMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    // Injected from SharedSecurityAutoConfiguration
    private final SharedGatewayHeaderFilter sharedGatewayHeaderFilter;
    private final SharedSecurityExceptionHandler sharedSecurityExceptionHandler;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // Priority hook: Overrides the fallback bean in the library
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/auth/v1/login",
                                "/auth/v1/signup",
                                "/auth/v1/refresh",
                                "/auth/v1/logout",
                                "/auth/v1/logout-all",
                                "/h2-console/**",
                                "/.well-known/jwks.json"
                        ).permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll() // CORS preflight
                        .anyRequest().authenticated()
                )
                .exceptionHandling(ex -> ex
                        // Both security exception hooks now delegate to library handlers!
                        .authenticationEntryPoint(sharedSecurityExceptionHandler)
                        .accessDeniedHandler(sharedSecurityExceptionHandler)
                )
                .headers(headers -> headers
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
                )
                .addFilterBefore(sharedGatewayHeaderFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}

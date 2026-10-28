package com.crowdsource.security.shared.config;

import com.crowdsource.security.shared.filter.SharedGatewayHeaderFilter;
import com.crowdsource.security.shared.handler.SharedSecurityExceptionHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity // Automatically hooks in @PreAuthorize downstream capability!
public class SharedSecurityAutoConfiguration {

    @Bean
    public SharedGatewayHeaderFilter sharedGatewayHeaderFilter() {
        return new SharedGatewayHeaderFilter();
    }

    @Bean
    public SharedSecurityExceptionHandler sharedSecurityExceptionHandler() {
        return new SharedSecurityExceptionHandler();
    }

    @Bean
    public SecurityFilterChain sharedSecurityFilterChain(HttpSecurity http, SharedGatewayHeaderFilter filter) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll()) // Gateway holds URL blocks
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}

package com.crowdsource.security.shared.config;

import com.crowdsource.security.shared.filter.SharedGatewayHeaderFilter;
import com.crowdsource.security.shared.handler.SharedSecurityExceptionHandler;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * Default, fail-closed security for every downstream service sitting behind the API gateway.
 * <ul>
 *   <li>Stateless; CSRF/session/form/basic disabled (authentication happens at the gateway).</li>
 *   <li>Identity comes only from HMAC-signed gateway headers ({@link SharedGatewayHeaderFilter}).</li>
 *   <li>Every request requires authentication unless its path is listed in
 *       {@code security.shared.public-paths} (plus actuator health/info and {@code /error}).</li>
 *   <li>Method security ({@code @PreAuthorize}) is enabled for fine-grained RBAC.</li>
 * </ul>
 * A service can replace the whole chain by declaring its own {@link SecurityFilterChain} bean.
 */
// String names (not classes): Boot 4 moved the security auto-configurations into spring-boot-security; listing both the
// old and the new locations keeps the ordering correct without a compile-time dependency on either.
@AutoConfiguration(beforeName = {
        "org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration",
        "org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration"
})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(SharedSecurityProperties.class)
@EnableWebSecurity
@EnableMethodSecurity
public class SharedSecurityAutoConfiguration {

    private static final int MIN_SECRET_LENGTH = 32;

    @Bean
    @ConditionalOnMissingBean
    public SharedSecurityExceptionHandler sharedSecurityExceptionHandler() {
        return new SharedSecurityExceptionHandler();
    }

    /**
     * Services behind the gateway have no username/password login. Declaring a UserDetailsService stops Spring Boot's
     * UserDetailsServiceAutoConfiguration from creating its default in-memory user ("Using generated security
     * password"). It never authenticates anybody. Services that really need one (user-service) define their own bean,
     * and this one backs off.
     */
    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService denyAllUserDetailsService() {
        return username -> {
            throw new UsernameNotFoundException("Password login is not supported by this service");
        };
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain sharedSecurityFilterChain(HttpSecurity http,
                                                         SharedSecurityProperties properties,
                                                         SharedSecurityExceptionHandler exceptionHandler,
                                                         Environment environment) throws Exception {

        String secret = properties.getGatewaySecret();
        if (!StringUtils.hasText(secret) || secret.length() < MIN_SECRET_LENGTH) {
            throw new IllegalStateException("security.shared.gateway-secret must be set to a value of at least "
                    + MIN_SECRET_LENGTH + " characters (use the same value as the api-gateway)");
        }

        // NOT a bean on purpose, see SharedGatewayHeaderFilter javadoc.
        SharedGatewayHeaderFilter gatewayFilter =
                new SharedGatewayHeaderFilter(secret, properties.getMaxClockSkew(), exceptionHandler);

        List<String> publicPaths = new ArrayList<>(List.of("/actuator/health/**", "/actuator/info", "/error"));
        publicPaths.addAll(properties.getPublicPaths());

        boolean h2Console = environment.getProperty("spring.h2.console.enabled", Boolean.class, false);
        if (h2Console) {
            publicPaths.add(environment.getProperty("spring.h2.console.path", "/h2-console") + "/**");
        }

        // Spring Security 7 removed AntPathRequestMatcher / MvcRequestMatcher; PathPatternRequestMatcher is the replacement
        // (and avoids the MVC-matcher ambiguity when extra servlets such as the H2 console are registered).
        PathPatternRequestMatcher.Builder matchers = PathPatternRequestMatcher.withDefaults();
        RequestMatcher[] publicMatchers = publicPaths.stream()
                .<RequestMatcher>map(matchers::matcher)
                .toArray(RequestMatcher[]::new);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(exceptionHandler)
                        .accessDeniedHandler(exceptionHandler))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicMatchers).permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(gatewayFilter, UsernamePasswordAuthenticationFilter.class);

        if (h2Console) {
            http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));
        }

        return http.build();
    }
}

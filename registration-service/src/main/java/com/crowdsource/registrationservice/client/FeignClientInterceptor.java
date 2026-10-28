package com.crowdsource.registrationservice.client;

import feign.RequestInterceptor;
import feign.RequestTemplate;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Component
public class FeignClientInterceptor implements RequestInterceptor {

    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Override
    public void apply(RequestTemplate requestTemplate) {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder
                .getRequestAttributes())
                .getRequest();

        String authHeader = request.getHeader(AUTHORIZATION_HEADER);
        log.info("FeignClientInterceptor authHeader: {}", authHeader);
        if (authHeader != null) {
            requestTemplate.header(AUTHORIZATION_HEADER, authHeader);
        }

        // Optional: Add correlation ID for tracing
        String correlationId = request.getHeader("X-Correlation-Id");
        if (correlationId != null) {
            requestTemplate.header("X-Correlation-Id", correlationId);
        }
    }
}

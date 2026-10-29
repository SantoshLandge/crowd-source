package com.crowdsource.registrationservice.config;

import com.crowdsource.security.shared.model.GatewayHeaders;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;

/**
 * Forwards the caller's signed gateway identity headers to downstream services, so event-service and
 * payment-service authorize the call as the original end user (the signature stays valid for the clock-skew window).
 */
public class GatewayHeaderPropagationInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            HttpServletRequest incoming = attributes.getRequest();
            for (String header : GatewayHeaders.ALL) {
                String value = incoming.getHeader(header);
                if (value != null) {
                    request.getHeaders().set(header, value);
                }
            }
        }
        return execution.execute(request, body);
    }
}

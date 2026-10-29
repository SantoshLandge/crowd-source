package com.crowdsource.registrationservice.config;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    /** Resolves http://<service-id> through Eureka + client side load balancing. Clients must clone() it. */
    @Bean
    @LoadBalanced
    public RestClient.Builder loadBalancedRestClientBuilder() {
        return RestClient.builder().requestInterceptor(new GatewayHeaderPropagationInterceptor());
    }
}

package com.crowdsource.registrationservice.client;

import com.crowdsource.registrationservice.dto.PaymentResult;
import com.crowdsource.registrationservice.exception.UpstreamServiceException;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.math.BigDecimal;

@Component
public class PaymentClient {

    private final RestClient client;

    public PaymentClient(@LoadBalanced RestClient.Builder builder) {
        this.client = builder.clone().baseUrl("http://payment-service").build();
    }

    /** Idempotent per registrationId on the payment side. HTTP 402 is a normal "payment declined" result. */
    public PaymentResult process(String registrationId, BigDecimal amount) {
        try {
            return client.post()
                    .uri("/v1/payments/process?registrationId={r}&amount={a}", registrationId, amount.toPlainString())
                    .retrieve().body(PaymentResult.class);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode().value() == 402) {
                return new PaymentResult(null, null, "FAILED");
            }
            throw new UpstreamServiceException("payment-service rejected the request: " + e.getStatusCode(), e);
        } catch (RestClientException e) {
            throw new UpstreamServiceException("payment-service call failed", e);
        }
    }

    public void refund(Long paymentId) {
        try {
            client.post().uri("/v1/payments/refund/{id}", paymentId).retrieve().toBodilessEntity();
        } catch (RestClientException e) {
            throw new UpstreamServiceException("payment-service call failed", e);
        }
    }
}

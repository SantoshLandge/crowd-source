package com.crowdsource.registrationservice.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.math.BigDecimal;

@FeignClient(name = "payment-service")
public interface PaymentClient {

    @PostMapping("/v1/payments/process")
    String processPayment(@RequestParam String registrationId, @RequestParam BigDecimal amount);

    @PostMapping("/v1/payments/refund/{paymentId}")
    void processRefund(@PathVariable("paymentId") String paymentId);
}

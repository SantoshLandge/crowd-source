package com.crowdsource.paymentservice.controller;

import com.crowdsource.paymentservice.service.PaymentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

@RestController
@RequestMapping("/v1/payments")
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentService paymentService;

    @PostMapping("/process")
    public ResponseEntity<String> processPayment(
            @RequestParam String registrationId,
            @RequestParam BigDecimal amount) {
        String paymentId = paymentService.processPayment(registrationId, amount);
        return ResponseEntity.ok(paymentId);
    }

    @PostMapping("/refund/{paymentId}")
    public ResponseEntity<Void> refund(@PathVariable Long paymentId) {
        paymentService.processRefund(paymentId);
        return ResponseEntity.ok().build();
    }
}

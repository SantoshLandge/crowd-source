package com.crowdsource.paymentservice.controller;

import com.crowdsource.paymentservice.dto.PaymentResponse;
import com.crowdsource.paymentservice.service.PaymentService;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

/**
 * INTERNAL API: called by registration-service only (there is deliberately no gateway route). Callers must still
 * present the signed gateway identity headers, enforced by the shared security chain.
 * Never expose these endpoints publicly: the amount is supplied by the caller.
 */
@RestController
@RequestMapping("/v1/payments")
@RequiredArgsConstructor
public class PaymentController {

    private final PaymentService paymentService;

    @PostMapping("/process")
    public ResponseEntity<PaymentResponse> processPayment(
            @RequestParam @NotBlank String registrationId,
            @RequestParam @DecimalMin(value = "0.01") BigDecimal amount) {
        PaymentResponse result = paymentService.processPayment(registrationId, amount);
        HttpStatus status = PaymentService.SUCCESS.equals(result.status()) ? HttpStatus.OK : HttpStatus.PAYMENT_REQUIRED;
        return ResponseEntity.status(status).body(result);
    }

    @PostMapping("/refund/{paymentId}")
    public ResponseEntity<PaymentResponse> refund(@PathVariable Long paymentId) {
        return ResponseEntity.ok(paymentService.processRefund(paymentId));
    }
}

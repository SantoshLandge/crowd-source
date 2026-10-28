package com.crowdsource.paymentservice.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "payments")
public class Payment {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String registrationId;
    private BigDecimal amount;
    private String status; // PENDING, SUCCESS, FAILED, REFUNDED
    private String transactionId;
    private LocalDateTime paymentDate;
}

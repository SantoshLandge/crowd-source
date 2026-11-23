package com.crowdsource.paymentservice.entity;

import java.util.UUID;
import org.hibernate.annotations.UuidGenerator;
import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "payments")
public class Payment {
    @Id
    @UuidGenerator(style = UuidGenerator.Style.VERSION_7)
    @Column(updatable = false, nullable = false)
    private UUID id;

    private UUID registrationId;
    private BigDecimal amount;
    private String status; // PENDING, SUCCESS, FAILED, REFUNDED
    private String transactionId;
    private LocalDateTime paymentDate;
}

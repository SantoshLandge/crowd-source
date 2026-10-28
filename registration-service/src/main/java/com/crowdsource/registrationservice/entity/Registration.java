package com.crowdsource.registrationservice.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Data
@Table(name = "registrations")
public class Registration {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long eventId;
    private String attendeeName;
    private String attendeeEmail;
    private Integer ticketQuantity;
    private BigDecimal totalAmount;
    private String status; // PENDING, CONFIRMED, CANCELLED
    private LocalDateTime registrationDate;
    private String paymentId;
}

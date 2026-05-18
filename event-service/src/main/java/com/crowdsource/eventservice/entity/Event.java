package com.crowdsource.eventservice.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Data
@Table(name = "events")
public class Event {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String name;

    private String description;
    private Integer totalCapacity;
    private Integer availableCapacity;
    private LocalDateTime eventDate;
    private String status;

    @Version
    private Integer version;
}

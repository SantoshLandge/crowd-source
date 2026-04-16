package com.crowdsource.eventservice.entity;

import com.crowdsource.eventservice.entity.type.EventStatus;
import com.crowdsource.eventservice.entity.type.EventType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "events")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Event {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    private EventType type;  // VIRTUAL/PHYSICAL

    private String venue;  // Physical addr or virtual URL

    private Integer capacity;

    @Enumerated(EnumType.STRING)
    private EventStatus status = EventStatus.DRAFT;  // DRAFT/PENDING/LIVE/CANCELLED

    private LocalDateTime startAt;
    private LocalDateTime endAt;

    @Column(name = "organizer_id")  // FK ref User.id (no @ManyToOne for decoupling)
    private Long organizerId;

    @CreationTimestamp
    private LocalDateTime createdAt;
}

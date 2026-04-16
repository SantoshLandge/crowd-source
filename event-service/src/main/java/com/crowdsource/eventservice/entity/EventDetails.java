package com.crowdsource.eventservice.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "event_details")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EventDetails {
    @Id
    private Long eventId;  // Matches Event.id

    private String imageUrl;

    @JdbcTypeCode(SqlTypes.JSON)  // Dynamic metadata (Jmix-like)
    private String metadata;  // {"tags": [], "agenda": []}
}

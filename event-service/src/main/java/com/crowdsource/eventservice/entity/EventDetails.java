package com.crowdsource.eventservice.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
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

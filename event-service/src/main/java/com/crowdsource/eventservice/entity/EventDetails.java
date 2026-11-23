package com.crowdsource.eventservice.entity;

import java.util.UUID;
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
    private UUID eventId;  // shares the primary key of its Event (assigned, not generated)

    private String imageUrl;

    @JdbcTypeCode(SqlTypes.JSON)
    private String metadata;
}

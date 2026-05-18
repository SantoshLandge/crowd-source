package com.crowdsource.eventservice.repository;

import com.crowdsource.eventservice.entity.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;
import java.util.UUID;

public interface EventRepository extends JpaRepository<Event, Long> {

    @Modifying
    @Transactional
    @Query("UPDATE Event e SET e.availableCapacity = e.availableCapacity - :quantity " +
           "WHERE e.id = :eventId AND e.availableCapacity >= :quantity")
    int reduceCapacity(@Param("eventId") Long eventId, @Param("quantity") int quantity);

    @Modifying
    @Transactional
    @Query("UPDATE Event e SET e.availableCapacity = e.availableCapacity + :quantity " +
           "WHERE e.id = :eventId")
    int increaseCapacity(@Param("eventId") Long eventId, @Param("quantity") int quantity);
}

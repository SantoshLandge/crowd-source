package com.crowdsource.eventservice.kafka;

import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EventKafkaConsumer {
    @KafkaListener(topics = "event-approved", groupId = "event-group")
    public void handleEventApproved(Object eventData) {
        // Parse eventId → Update status to LIVE
        log.info("Received approved: {}", eventData);
    }
}

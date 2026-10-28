package com.crowdsource.registrationservice.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "event-service")
public interface EventClient {

    @GetMapping("/v1/event/{id}/capacity")
    Integer checkCapacity(@PathVariable("id") Long eventId);

    @PostMapping("/v1/event/{id}/capacity/hold")
    void holdCapacity(@PathVariable("id") Long eventId, @RequestParam int quantity);

    @PostMapping("/v1/event/{id}/capacity/confirm")
    void confirmCapacity(@PathVariable("id") Long eventId, @RequestParam int quantity);

    @PostMapping("/v1/event/{id}/capacity/release")
    void releaseCapacity(@PathVariable("id") Long eventId, @RequestParam int quantity);
}

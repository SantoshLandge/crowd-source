package com.crowdsource.registrationservice.client;

import com.crowdsource.registrationservice.dto.EventView;
import com.crowdsource.registrationservice.exception.RegistrationConflictException;
import com.crowdsource.registrationservice.exception.RegistrationNotFoundException;
import com.crowdsource.registrationservice.exception.UpstreamServiceException;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class EventClient {

    private final RestClient client;

    public EventClient(@LoadBalanced RestClient.Builder builder) {
        this.client = builder.clone().baseUrl("http://event-service").build();
    }

    public EventView getEvent(Long eventId) {
        try {
            return client.get().uri("/v1/event/{id}", eventId).retrieve().body(EventView.class);
        } catch (HttpClientErrorException.NotFound e) {
            throw new RegistrationNotFoundException("Event " + eventId + " not found");
        } catch (RestClientException e) {
            throw new UpstreamServiceException("event-service call failed", e);
        }
    }

    /** Atomically reserves seats; 409 from event-service means sold out / not open. */
    public void reserve(Long eventId, int quantity) {
        try {
            client.post().uri("/v1/event/{id}/capacity/reserve?quantity={q}", eventId, quantity)
                    .retrieve().toBodilessEntity();
        } catch (HttpClientErrorException.Conflict e) {
            throw new RegistrationConflictException("Not enough tickets available");
        } catch (HttpClientErrorException.NotFound e) {
            throw new RegistrationNotFoundException("Event " + eventId + " not found");
        } catch (RestClientException e) {
            throw new UpstreamServiceException("event-service call failed", e);
        }
    }

    public void release(Long eventId, int quantity) {
        try {
            client.post().uri("/v1/event/{id}/capacity/release?quantity={q}", eventId, quantity)
                    .retrieve().toBodilessEntity();
        } catch (RestClientException e) {
            throw new UpstreamServiceException("event-service call failed", e);
        }
    }
}

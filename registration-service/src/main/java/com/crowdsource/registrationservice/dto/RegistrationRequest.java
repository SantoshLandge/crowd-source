package com.crowdsource.registrationservice.dto;

import lombok.Data;

@Data
public class RegistrationRequest {

    private Long eventId;
    private Integer ticketQuantity;
    private String attendeeName;
    private String attendeeEmail;

}

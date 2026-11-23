package com.crowdsource.registrationservice.dto;

import java.util.UUID;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record EventView(UUID id, String title, Integer ticketPrice, String status) {
}

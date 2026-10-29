package com.crowdsource.registrationservice.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record EventView(Long id, String title, Integer ticketPrice, String status) {
}

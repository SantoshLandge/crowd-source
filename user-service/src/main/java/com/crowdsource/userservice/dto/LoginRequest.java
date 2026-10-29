package com.crowdsource.userservice.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "password")
public class LoginRequest {

    @NotBlank
    private String username;   // the account's e-mail
    @NotBlank
    private String password;
}

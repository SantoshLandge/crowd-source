package com.crowdsource.userservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "password")
public class SignupRequest {

    @NotBlank
    @Email(message = "Valid email required")
    private String email;

    @NotBlank
    @Size(min = 3, max = 20)
    private String displayName;

    // 72 = BCrypt's input limit; the old max of 16 needlessly prevented strong passphrases
    @NotBlank
    @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
    private String password;
}

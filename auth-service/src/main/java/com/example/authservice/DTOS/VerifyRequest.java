package com.example.authservice.DTOS;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class VerifyRequest {
    @NotNull @Email
    private String email;
    @NotNull
    private String otp;
}

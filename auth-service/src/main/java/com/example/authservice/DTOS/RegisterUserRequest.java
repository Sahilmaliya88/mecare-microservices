package com.example.authservice.DTOS;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class RegisterUserRequest {
    @NotNull(message = "email can't be null") @Email(message = "please enter valid email")
    private String email;
    @NotNull(message = "password can't be null")
    private String password;
}

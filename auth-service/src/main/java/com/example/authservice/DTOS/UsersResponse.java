package com.example.authservice.DTOS;

import java.util.UUID;

import com.example.authservice.Entities.UserProfileEntity;
import com.example.authservice.utils.enums.LoginProviders;
import com.example.authservice.utils.enums.UserRoles;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class UsersResponse {
    private UUID id;
    private String email;
    private String role;
    private Boolean isVerified;
    private LoginProviders provider;
    private UserProfileEntity user_profile;

    UsersResponse(UUID id, String email, UserRoles role, boolean is_verified, LoginProviders provider,
            UserProfileEntity user_profile) {
        this.id = id;
        this.email = email;
        this.role = role.toString();
        this.isVerified = is_verified;
        this.provider = provider;
        this.user_profile = user_profile;

    }

}

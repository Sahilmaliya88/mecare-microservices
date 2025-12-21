package com.example.authservice.DTOS;

import lombok.Data;
import lombok.ToString;

/**
 *Data transfer Object for Google Profile response
 */
@Data
@ToString
public class GoogleUserProfileResponse {
    private final String family_name;
    private final String name;
    private final String email;
    private final String given_name;
    private final String id;
    private final String verified_email;
}

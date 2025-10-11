package com.example.authservice.DTOS;

import java.util.Optional;

import com.example.authservice.utils.DeviceInfo;
import com.example.authservice.utils.LoginProviders;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

/**
 * Data Transfer Object for social login requests.
 * Encapsulates the necessary information for authenticating users via social
 * login providers.
 */
@Getter
@Builder
@ToString
public class SocialLoginRequest {
    /**
     * The access token provided by the social login provider.
     * Must not be blank and should be within reasonable length limits.
     */
    @NotBlank(message = "Access token is required!")
    @Size(min = 1, max = 1000, message = "Access token length must be between 1 and 1000 characters")
    private final String accessToken;

    /**
     * The social login provider (e.g., GOOGLE, FACEBOOK, GITHUB).
     * Must not be null.
     */
    @NotNull(message = "Provider is required!")
    private final LoginProviders provider;

    /**
     * Optional refresh token provided by the social login provider.
     * Can be used for token refresh operations.
     */
    @Size(max = 1000, message = "Refresh token length must not exceed 1000 characters")
    private final String refreshToken;

    /**
     * Optional API version for the social login request.
     * Useful for handling different versions of provider APIs.
     */
    @Size(max = 10, message = "API version must not exceed 10 characters")
    private final String apiVersion;

    /**
     * Optional redirect URI used in the OAuth flow.
     * Useful for validating the redirect URI against the provider's configuration.
     */
    @Size(max = 200, message = "Redirect URI must not exceed 200 characters")
    private final String redirectUri;

    @NotNull(message = "Device info is required")
    private final DeviceInfo deviceInfo;

    /**
     * Gets the refresh token wrapped in an Optional.
     * 
     * @return Optional containing the refresh token if present, empty otherwise
     */
    public Optional<String> getRefreshToken() {
        return Optional.ofNullable(refreshToken);
    }

    /**
     * Gets the API version wrapped in an Optional.
     * 
     * @return Optional containing the API version if present, empty otherwise
     */
    public Optional<String> getApiVersion() {
        return Optional.ofNullable(apiVersion);
    }

    /**
     * Gets the redirect URI wrapped in an Optional.
     * 
     * @return Optional containing the redirect URI if present, empty otherwise
     */
    public Optional<String> getRedirectUri() {
        return Optional.ofNullable(redirectUri);
    }
}
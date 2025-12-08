package com.example.authservice.controllers;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.example.authservice.DTOS.UserProfileRequest;
import com.example.authservice.services.UserService;

import io.imagekit.sdk.exceptions.BadRequestException;
import io.imagekit.sdk.exceptions.ForbiddenException;
import io.imagekit.sdk.exceptions.InternalServerException;
import io.imagekit.sdk.exceptions.TooManyRequestsException;
import io.imagekit.sdk.exceptions.UnauthorizedException;
import io.imagekit.sdk.exceptions.UnknownException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@Tag(name = "User managements API", description = "APIs for user management")
@RequestMapping("/api/v1/user")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping(value = "/profile/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Get user profile", description = "API to get user profile information")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> setProfile(@ModelAttribute @Valid UserProfileRequest request) {
        log.info("Received request to get user profile for userId");
        userService.createUserProfile(request, null);
        Map<String, Object> response = Map.of("message", "User profile created successfully", "status", true);
        return ResponseEntity.ok(response);
    }

    @PostMapping(value = "{user_id}/profile/create", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "set user profile for specific user", description = "API to get user profile information for specific user by admin")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile retrieved successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN')")
    public ResponseEntity<?> setProfileByAdmin(@PathVariable("user_id") String userId,
            @ModelAttribute @Valid UserProfileRequest request) {

        log.info("Received request to get user profile for userId: {}", request.getFirstName());
        userService.createUserProfile(request, UUID.fromString(userId));
        Map<String, Object> response = Map.of("message", "User profile created successfully", "status", true);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping("/profile/photo/upload")
    @Operation(summary = "Upload profile photo", description = "API to upload user profile photo")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Profile photo uploaded successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<?> uploadProfilePhoto(@RequestBody MultipartFile file) {
        log.info("Received request to upload profile photo");
        try {
            userService.UploadProfilePicture(file, null);
        } catch (IOException | InternalServerException | BadRequestException | UnknownException | ForbiddenException
                | TooManyRequestsException | UnauthorizedException e) {
            log.error("Error uploading profile photo: {}", e.getMessage());
            throw new RuntimeException(e);
        }
        Map<String, Object> response = Map.of("message", "Profile photo uploaded successfully", "status", true);
        return ResponseEntity.ok(response);
    }
}

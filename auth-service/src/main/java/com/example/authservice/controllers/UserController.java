package com.example.authservice.controllers;

import java.util.Map;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.authservice.DTOS.UserProfileRequest;
import com.example.authservice.services.UserService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
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
    @PatchMapping("/profile/update")
    @Operation(summary = "Update user profile", description = "API to update user profile information")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<?> updateMyProfile(@ModelAttribute UserProfileRequest request) {
        log.info("updating profile");
        userService.updateUserProfile(request, null);
        Map<String, Object> response = Map.of("message", "User profile updated successfully", "status", true);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("{user_id}/profile/update")
    @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN')")
    @Operation(summary = "Update user profile by admin", description = "API to update user profile information for specific user by admin")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile updated successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<?> updateUserProfileByAdmin(@PathVariable("user_id") String userId,
            @ModelAttribute UserProfileRequest request) {
        log.info("Admin updating profile for userId: {}", userId);
        userService.updateUserProfile(request, UUID.fromString(userId));
        Map<String, Object> response = Map.of("message", "User profile updated successfully", "status", true);
        return ResponseEntity.ok(response);
    }

    @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
    @Operation(summary = "Delete user profile", description = "API to delete user profile")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User profile deleted successfully"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    @DeleteMapping("{user_id}/profile/delete")
    public ResponseEntity<?> deleteUserProfile(@PathVariable("user_id") @NotBlank String userId) {
        log.info("Received request to delete user profile for userId: {}", userId);
        userService.deleteUserProfile(UUID.fromString(userId));
        Map<String, Object> response = Map.of("message", "User profile deleted successfully", "status", true);
        return ResponseEntity.ok(response);
    }
}

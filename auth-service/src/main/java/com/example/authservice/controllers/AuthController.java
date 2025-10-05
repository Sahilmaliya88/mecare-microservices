package com.example.authservice.controllers;

import com.example.authservice.DTOS.*;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.services.AuthService;
import com.example.authservice.utils.annotations.ValidCsvFile;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/v1/user")
@Tag(name = "Authentication API", description = "Endpoints for user authentication and profile management")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Operation(summary = "Health check", description = "Verify the auth service is up and running.")
    @ApiResponse(responseCode = "200", description = "Service is healthy")
    @GetMapping("/health")
    public String healthRoute(HttpServletRequest request){
        String userName= SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("hello {}",userName);
        return "Hello from auth service";
    }

    @Operation(summary = "Register new user", description = "Register a new user and return authentication token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User registered successfully",
                    content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"user registered successfully!\", \"token\": \"jwt-token\" }"))),
            @ApiResponse(responseCode = "400", description = "Invalid request body")
    })
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody @Valid RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        String token = authService.registerUser(registerUserRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","user registered successfully!","token",token));
    }

    @Operation(summary = "Login user", description = "Authenticate an existing user and return JWT token.")
    @ApiResponse(responseCode = "200", description = "Login successful",
            content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification successful\", \"token\": \"jwt-token\" }")))
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody @Valid RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        String token = authService.loginUser(registerUserRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Verification successful","token",token));
    }

    @Operation(summary = "Verify profile", description = "Verify user profile via verification code.")
    @ApiResponse(responseCode = "200", description = "Verification successful",
            content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification successful\", \"token\": \"jwt-token\" }")))
    @PatchMapping("/verify-profile")
    public ResponseEntity<?> verifyUser(@RequestBody @Valid VerifyRequest verifyRequest) throws JsonProcessingException {
        String token = authService.verifyUser(verifyRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Verification successful","token",token));
    }

    @Operation(summary = "Get current user", description = "Get details of the currently authenticated user.")
    @PreAuthorize("isAuthenticated()")
    @ApiResponse(responseCode = "200", description = "User details fetched successfully",
            content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"user details successfully fetched\", \"user\": { \"id\": 1, \"email\": \"test@example.com\" } }")))
    @GetMapping("/me")
    public ResponseEntity<?> getMe(){
        UserEntity userEntity = authService.getAuthenticatedUser();
        return ResponseEntity.ok(Map.of("message","user details successfully fetched","user",userEntity));
    }

    @Operation(summary = "Send verification code", description = "Send email verification code to the authenticated user.")
    @PreAuthorize("isAuthenticated()")
    @ApiResponse(responseCode = "200", description = "Verification code sent",
            content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification sent!.please check email.\" }")))
    @GetMapping("/get-verification-code")
    public ResponseEntity<?> getVerificationCode(){
        authService.sendVerificationCode();
        return ResponseEntity.of(Optional.of(Map.of("status", true, "message", "Verification sent!.please check email.")));
    }

    @Operation(summary = "Forgot password", description = "Send a password reset link to the provided email.")
    @ApiResponse(responseCode = "200", description = "Password reset link sent",
            content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Password reset link sent successfully!\" }")))
    @GetMapping("/forgot-password/{email}")
    public ResponseEntity<?> forgotPasswordLink(@Parameter(description = "Email address of the user") @PathVariable String email){
        authService.sendPasswordResetLink(email);
        return ResponseEntity
                .ok(Map.of("status", "true",
                        "message","Password reset link sent successfully!"));
    }

    @Operation(summary = "Reset password", description = "Reset user password using a reset token.")
    @ApiResponse(responseCode = "200", description = "Password reset successfully",
            content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Password changed successfully, Please login again\" }")))
    @PatchMapping("/reset-password/{token}")
    public ResponseEntity<?> resetPassword(@Parameter(description = "Reset token") @PathVariable @NotNull String token,
                                           @RequestBody ResetPasswordRequest resetPasswordRequest){
        authService.changePassword(token,resetPasswordRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Password changed successfully, Please login again"));
    }

    @Operation(summary = "Social login", description = "Authenticate user via social login (Google, Facebook, etc.)")
    @ApiResponse(responseCode = "200", description = "Logged in successfully",
            content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"logged in successfully\", \"token\": \"jwt-token\" }")))
    @PostMapping("social-login")
    public ResponseEntity<?> socialLoginController(@RequestBody @Valid SocialLoginRequest socialLoginRequestBody,HttpServletRequest request){
        String token = authService.socialLogin(socialLoginRequestBody);
        Map<String,Object> response = Map.
                of("message","logged in successfully",
                        "token",token);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Change user role", description = "Change the role of a specific user by email.")
    @PreAuthorize("isAuthenticated()")
    @ApiResponse(responseCode = "200", description = "Role changed successfully",
            content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"role changed\" }")))
    @PatchMapping("/role")
    public ResponseEntity<Map<String,Object>> changeUserRoleController(
            @RequestBody @Valid ChangeUserRoleRequest changeUserRoleRequest){
        authService.changeUserRole(changeUserRoleRequest);
        Map<String,Object> response = Map.of("message","role changed");
        return ResponseEntity.ok(response);
    }
    @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
    @PostMapping("/insert")
    public ResponseEntity<Map<String,Object>> insertUsers(@ModelAttribute @Valid UploadCsvRequest request){
        log.info("received file with name {}",request.getFile().getOriginalFilename());
        int insertedRecord = authService.insertUsers(request);
        Map<String,Object> response = Map.of("status",true,"message","data inserted successfully","total",insertedRecord);
        return ResponseEntity.ok(response);
    }
}



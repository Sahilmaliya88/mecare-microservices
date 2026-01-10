package com.mecare.authservice.controllers;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.mecare.authservice.DTOS.ChangePasswordRequest;
import com.mecare.authservice.DTOS.ChangeUserRoleRequest;
import com.mecare.authservice.DTOS.RegisterUserRequest;
import com.mecare.authservice.DTOS.ResetPasswordRequest;
import com.mecare.authservice.DTOS.SocialLoginRequest;
import com.mecare.authservice.DTOS.UploadCsvRequest;
import com.mecare.authservice.DTOS.UsersResponse;
import com.mecare.authservice.DTOS.VerifyRequest;
import com.mecare.authservice.entities.UserEntity;
import com.mecare.authservice.services.AuthService;
import com.mecare.authservice.utils.enums.LoginProviders;
import com.mecare.authservice.utils.enums.UserRoles;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication API", description = "Endpoints for user authentication and profile management")
public class authController {

        @Autowired
        private AuthService authService;

        @Operation(summary = "Health check", description = "Verify the auth service is up and running.")
        @ApiResponse(responseCode = "200", description = "Service is healthy")
        @GetMapping("/health")
        public String healthRoute(HttpServletRequest request) {
                String userName = SecurityContextHolder.getContext().getAuthentication().getName();
                log.info("hello {}", userName);
                return "Hello from auth service";
        }

        @Operation(summary = "Register new user", description = "Register a new user and return authentication token.")
        @ApiResponses({
                        @ApiResponse(responseCode = "200", description = "User registered successfully", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"user registered successfully!\", \"token\": \"jwt-token\" }"))),
                        @ApiResponse(responseCode = "400", description = "Invalid request body")
        })
        @PostMapping("/register")
        public ResponseEntity<?> registerUser(@RequestBody @Valid RegisterUserRequest registerUserRequest,
                        HttpServletRequest request)
                        throws JsonProcessingException {
                String token = authService.registerUser(registerUserRequest, request);
                return ResponseEntity
                                .ok(Map.of("status", true, "message", "user registered successfully!", "token", token));
        }

        @Operation(summary = "Login user", description = "Authenticate an existing user and return JWT token.")
        @ApiResponse(responseCode = "200", description = "Login successful", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification successful\", \"token\": \"jwt-token\" }")))
        @PostMapping("/login")
        public ResponseEntity<?> loginUser(@RequestBody @Valid RegisterUserRequest registerUserRequest,
                        HttpServletRequest request)
                        throws JsonProcessingException {
                String token = authService.loginUser(registerUserRequest, request);
                return ResponseEntity.ok(Map.of("status", true, "message", "Verification successful", "token", token));
        }

        @Operation(summary = "Verify profile", description = "Verify user profile via verification code.")
        @ApiResponse(responseCode = "200", description = "Verification successful", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification successful\", \"token\": \"jwt-token\" }")))
        @PatchMapping("/verify-profile")
        public ResponseEntity<?> verifyUser(@RequestBody @Valid VerifyRequest verifyRequest, HttpServletRequest request)
                        throws JsonProcessingException {
                String token = authService.verifyUser(verifyRequest, request);
                return ResponseEntity.ok(Map.of("status", true, "message", "Verification successful", "token", token));
        }

        @Operation(summary = "Get current user", description = "Get details of the currently authenticated user.")
        @PreAuthorize("isAuthenticated()")
        @ApiResponse(responseCode = "200", description = "User details fetched successfully", content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"user details successfully fetched\", \"user\": { \"id\": 1, \"email\": \"test@example.com\" } }")))
        @GetMapping("/me")
        public ResponseEntity<?> getMe() {
                UserEntity userEntity = authService.getAuthenticatedUser();
                return ResponseEntity.ok(Map.of("message", "user details successfully fetched", "user", userEntity));
        }

        @Operation(summary = "Send verification code", description = "Send email verification code to the authenticated user.")
        @PreAuthorize("isAuthenticated()")
        @ApiResponse(responseCode = "200", description = "Verification code sent", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Verification sent!.please check email.\" }")))
        @GetMapping("/get-verification-code")
        public ResponseEntity<?> getVerificationCode() {
                authService.sendVerificationCode();
                return ResponseEntity.of(Optional
                                .of(Map.of("status", true, "message", "Verification sent!.please check email.")));
        }

        @Operation(summary = "Forgot password", description = "Send a password reset link to the provided email.")
        @ApiResponse(responseCode = "200", description = "Password reset link sent", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Password reset link sent successfully!\" }")))
        @GetMapping("/forgot-password/{email}")
        public ResponseEntity<?> forgotPasswordLink(
                        @Parameter(description = "Email address of the user") @PathVariable String email) {
                authService.sendPasswordResetLink(email);
                return ResponseEntity
                                .ok(Map.of("status", "true",
                                                "message", "Password reset link sent successfully!"));
        }

        @Operation(summary = "Reset password", description = "Reset user password using a reset token.")
        @ApiResponse(responseCode = "200", description = "Password reset successfully", content = @Content(schema = @Schema(type = "object", example = "{ \"status\": true, \"message\": \"Password changed successfully, Please login again\" }")))
        @PatchMapping("/reset-password/{token}")
        public ResponseEntity<?> resetPassword(
                        @Parameter(description = "Reset token") @PathVariable @NotNull String token,
                        @RequestBody ResetPasswordRequest resetPasswordRequest) {
                authService.changePassword(token, resetPasswordRequest);
                return ResponseEntity.ok(
                                Map.of("status", true, "message", "Password changed successfully, Please login again"));
        }

        @Operation(summary = "Social login", description = "Authenticate user via social login (Google, Facebook, etc.)")
        @ApiResponse(responseCode = "200", description = "Logged in successfully", content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"logged in successfully\", \"token\": \"jwt-token\" }")))
        @PostMapping("social-login")
        public ResponseEntity<?> socialLoginController(@RequestBody @Valid SocialLoginRequest socialLoginRequestBody,
                        HttpServletRequest request) throws JsonProcessingException {
                String token = authService.socialLogin(socialLoginRequestBody, request);
                Map<String, Object> response = Map.of("message", "logged in successfully",
                                "token", token);
                return ResponseEntity.ok(response);
        }

        @Operation(summary = "Change user role", description = "Change the role of a specific user by email.")
        @PreAuthorize("isAuthenticated()")
        @ApiResponse(responseCode = "200", description = "Role changed successfully", content = @Content(schema = @Schema(type = "object", example = "{ \"message\": \"role changed\" }")))
        @PatchMapping("/role")
        public ResponseEntity<Map<String, Object>> changeUserRoleController(
                        @RequestBody @Valid ChangeUserRoleRequest changeUserRoleRequest, HttpServletRequest request) {
                authService.changeUserRole(changeUserRoleRequest, request);
                Map<String, Object> response = Map.of("message", "role changed");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @PostMapping("/insert")
        public ResponseEntity<Map<String, Object>> insertUsers(@ModelAttribute @Valid UploadCsvRequest request) {
                log.info("received file with name {}", request.getFile().getOriginalFilename());
                int insertedRecord = authService.insertUsers(request);
                Map<String, Object> response = Map.of("status", true, "message", "data inserted successfully", "total",
                                insertedRecord);
                return ResponseEntity.ok(response);
        }

        @Operation(summary = "Impersonate a user", description = """
                        Allows an admin or super admin to impersonate another user by their email.
                        Returns a JWT token that can be used to act on behalf of that user.
                        """, security = @SecurityRequirement(name = "bearerAuth"), responses = {
                        @ApiResponse(responseCode = "200", description = "Successfully impersonated user", content = @Content(mediaType = "application/json", schema = @Schema(example = "{\"status\": true, \"token\": \"<jwt_token_here>\"}"))),
                        @ApiResponse(responseCode = "400", description = "Invalid email format"),
                        @ApiResponse(responseCode = "403", description = "Access denied — insufficient privileges"),
                        @ApiResponse(responseCode = "500", description = "Server error while impersonating user")
        })
        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN')")
        @GetMapping("/{email}/impersonate")
        public ResponseEntity<Map<String, Object>> impersonateUser(@PathVariable @Email String email,
                        HttpServletRequest request)
                        throws JsonProcessingException {
                String token = authService.impersonateUser(email, request);
                Map<String, Object> response = Map.of("status", true, "token", token);
                return ResponseEntity.ok(response);
        }

        @Operation(summary = "End impersonating user", description = """
                        Operation end impersonating specific user and gives new jwt token of actual user
                        """, security = @SecurityRequirement(name = "bearerAuth"), responses = {
                        @ApiResponse(responseCode = "200", description = "Successfully impersonated user", content = @Content(mediaType = "application/json", schema = @Schema(example = "{\"status\": true, \"token\": \"<jwt_token_here>\"}"))),
                        @ApiResponse(responseCode = "400", description = "Invalid email format"),
                        @ApiResponse(responseCode = "403", description = "Access denied — insufficient privileges"),
                        @ApiResponse(responseCode = "500", description = "Server error while impersonating user")
        }

        )
        @PreAuthorize("isAuthenticated()")
        @GetMapping("impersonation/end")
        public ResponseEntity<Map<String, Object>> exitImpersonating(HttpServletRequest request)
                        throws JsonProcessingException {
                String token = authService.exitImpersonating(request);
                Map<String, Object> response = Map.of("status", true, "token", token);
                return ResponseEntity.ok(response);
        }

        @Operation(summary = "Change password", description = """
                        Allows authenticated user to change their password.
                        Requires the old password, new password, and an option to log out from other devices.
                        Returns a new JWT token upon successful password change.
                        """, security = @SecurityRequirement(name = "bearerAuth"), responses = {
                        @ApiResponse(responseCode = "200", description = "Password changed successfully", content = @Content(mediaType = "application/json", schema = @Schema(example = "{\"status\": true, \"token\": \"<new_jwt_token_here>\"}"))),
                        @ApiResponse(responseCode = "400", description = "Invalid request body or new password matches old password"),
                        @ApiResponse(responseCode = "401", description = "Unauthorized — invalid or missing authentication"),
                        @ApiResponse(responseCode = "500", description = "Server error while changing password")
        })
        @PreAuthorize("isAuthenticated()")
        @PatchMapping("change-password")
        public ResponseEntity<Map<String, Object>> changePassword(
                        @RequestBody @Valid ChangePasswordRequest changePasswordRequest, HttpServletRequest request) {
                String token = authService.updatePassword(changePasswordRequest, request);
                Map<String, Object> response = Map.of("status", true, "token", token);
                return ResponseEntity.ok(response);

        }

        @DeleteMapping("/{email}/delete")
        public ResponseEntity<Map<String, Object>> deleteUser(@PathVariable @Email String email,
                        @RequestParam(required = false) boolean hardDelete) {
                authService.deleteUserByEmail(email, hardDelete);
                Map<String, Object> response = Map.of("status", true, "message", "user deleted successfully");
                return ResponseEntity.ok(response);
        }

        @Operation(summary = "Logout user", description = """
                        Logs out the currently authenticated user.
                        If 'allDevice' is true, logs out from all devices; otherwise, logs out from the current device only.
                        Returns a success message upon completion.
                        """, security = @SecurityRequirement(name = "bearerAuth"), responses = {
                        @ApiResponse(responseCode = "200", description = "Logged out successfully", content = @Content(mediaType = "application/json", schema = @Schema(example = "{\"status\": true, \"message\": \"logged out successfully\"}"))),
                        @ApiResponse(responseCode = "401", description = "Unauthorized — invalid or missing authentication"),
                        @ApiResponse(responseCode = "500", description = "Server error while logging out")
        })
        @PreAuthorize("isAuthenticated()")
        @DeleteMapping("/logout")
        public ResponseEntity<Map<String, Object>> logoutUser(HttpServletRequest request,
                        @RequestParam(required = false) boolean all_device) {
                authService.logoutUser(request, all_device);
                Map<String, Object> response = Map.of("status", true, "message", "logged out successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @GetMapping("/all")
        public ResponseEntity<Map<String, Object>> getAllUsers(HttpServletRequest request,
                        @RequestParam(required = false) UserRoles role,
                        @RequestParam(required = false) String search,
                        @RequestParam(required = true) @Min(0) Integer page,
                        @RequestParam(required = true) @Min(0) @Max(100) Integer size,
                        @RequestParam(required = false) List<String> sort_by,
                        @RequestParam(required = false) String sort_dir,
                        @RequestParam(required = false) Boolean is_active,
                        @RequestParam(required = false) Boolean is_verified,
                        @RequestParam(required = false) LoginProviders provider) {
                var users = authService.getAllUsers(role, search, page, size, sort_by, sort_dir, is_active,
                                is_verified, provider);
                Map<String, Object> response = Map.of("status", true, "message", "users fetched successfully",
                                "response",
                                users);
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @GetMapping("/get-user/{id}")
        public ResponseEntity<Map<String, Object>> getUserById(@PathVariable @NotNull String id) {
                UsersResponse user = authService.getUserById(UUID.fromString(id));
                Map<String, Object> response = Map.of("status", true, "message", "user fetched successfully",
                                "user", user);
                return ResponseEntity.ok(response);
        }
}

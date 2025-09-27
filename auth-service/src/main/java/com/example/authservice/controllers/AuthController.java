package com.example.authservice.controllers;

import com.example.authservice.DTOS.RegisterUserRequest;
import com.example.authservice.DTOS.ResetPasswordRequest;
import com.example.authservice.DTOS.SocialLoginRequest;
import com.example.authservice.DTOS.VerifyRequest;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.services.AuthService;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/v1/user")
public class AuthController {
    @Autowired
    private AuthService authService;
    @GetMapping("/health")
    public String healthRoute(HttpServletRequest request){
        String userName= SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("hello {}",userName);
        return "Hello from auth service";
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody @Valid RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        String token = authService.registerUser(registerUserRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","user registered successfully!","token",token));
    }
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody @Valid RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        String token = authService.loginUser(registerUserRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Verification successful","token",token));
    }
    @PatchMapping("/verify-profile")
    public ResponseEntity<?> verifyUser(@RequestBody @Valid VerifyRequest verifyRequest) throws JsonProcessingException {
        String token = authService.verifyUser(verifyRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Verification successful","token",token));
    }
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getMe(){
        UserEntity userEntity = authService.getAuthenticatedUser();
        return ResponseEntity.ok(Map.of("message","user details successfully fetched","user",userEntity));
    }
    @GetMapping("/get-verification-code")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getVerificationCode(){
        authService.sendVerificationCode();
        return ResponseEntity.of(Optional.of(Map.of("status", true, "message", "Verification sent!.please check email.")));
    }

    @GetMapping("/forgot-password/{email}")
    public ResponseEntity<?> forgotPasswordLink(@PathVariable String email){
        authService.sendPasswordResetLink(email);
        return ResponseEntity
                .ok(Map.of("status", "true",
                                "message","Password reset link sent successfully!"));
    }

    @PatchMapping("/reset-password/{token}")
    public ResponseEntity<?> resetPassword(@PathVariable @NotNull String token,@RequestBody ResetPasswordRequest resetPasswordRequest){
        authService.changePassword(token,resetPasswordRequest);
        return ResponseEntity.ok(Map.of("status",true,"message","Password changed successfully, Please login again"));
    }
    @PostMapping("social-login")
    public ResponseEntity<?> socialLoginController(@RequestBody @Valid SocialLoginRequest socialLoginRequestBody,HttpServletRequest request){
        String token = authService.socialLogin(socialLoginRequestBody);
        Map<String,Object> response = Map.
                of("message","logged in successfully",
                        "token",token);
        return ResponseEntity.ok(response);
    }
}

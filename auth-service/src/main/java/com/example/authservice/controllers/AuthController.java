package com.example.authservice.controllers;

import com.example.authservice.DTOS.RegisterUserRequest;
import com.example.authservice.DTOS.VerifyRequest;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.services.AuthService;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

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
}

package com.mecare.authservice.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
@RequestMapping("/api/v1/auth/session")
@Tag(name = "Session Management API", description = "Endpoints for managing user sessions")
public class SessionController {
    // Session management endpoints would go here
}

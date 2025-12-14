package com.example.authservice.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.authservice.DTOS.ActionCategoryRequest;
import com.example.authservice.services.ActionService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/actions")
@Tag(name = "Actions Management", description = "Endpoints for managing audit actions and categories")
public class actionsController {
    private final ActionService actionService;

    @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
    @PostMapping("/categories/create")
    @Operation(summary = "Create Action Category", description = "Creates a new action category in the audit system")
    @ApiResponses(value = {
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Action category created successfully"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Invalid input data"),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "409", description = "Action category already exists")
    })
    public ResponseEntity<?> createAction(@RequestBody @Valid ActionCategoryRequest request) {
        actionService.auditCategoryCreation(request);
        Map<String, Object> response = Map.of("status", true, "message", "Action category created successfully");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

}

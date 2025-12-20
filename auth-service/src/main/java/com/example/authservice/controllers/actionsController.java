package com.example.authservice.controllers;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.service.annotation.DeleteExchange;
import org.springframework.web.service.annotation.PatchExchange;

import com.example.authservice.DTOS.ActionCategoryEditRequest;
import com.example.authservice.DTOS.ActionCategoryRequest;
import com.example.authservice.DTOS.ActionEditRequest;
import com.example.authservice.DTOS.ActionRequest;
import com.example.authservice.DTOS.ActionResponse;
import com.example.authservice.Entities.AuditActionCategoryEntity;
import com.example.authservice.services.ActionService;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
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
                Map<String, Object> response = Map.of("status", true, "message",
                                "Action category created successfully");
                return ResponseEntity.status(HttpStatus.CREATED).body(response);
        }

        @Operation(summary = "Get All Action Categories", description = "Retrieves all action categories from the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Action categories retrieved successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action categories not found")
        })
        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @GetMapping("/categories/all")
        public ResponseEntity<?> getAllCategories(@RequestParam(defaultValue = "false") boolean include_deleted) {
                List<AuditActionCategoryEntity> categories = actionService.getAllCategories(include_deleted);
                Map<String, Object> response = Map.of("status", true, "message",
                                "Action categories retrieved successfully",
                                "total_categories", categories.size(),
                                "data", categories);
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @Operation(summary = "Edit Action Category", description = "Edits an existing action category in the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Action category edited successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action category not found")
        })
        @PatchExchange("/categories/edit/{code}")
        public ResponseEntity<?> editCategory(@PathVariable @NotNull(message = "Code is required") String code,
                        @RequestBody @Valid ActionCategoryEditRequest request) {
                actionService.editCategory(request, code);
                Map<String, Object> response = Map.of("status", true, "message", "Action category edited successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @Operation(summary = "Delete Action Category", description = "Deletes an existing action category in the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Action category deleted successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action category not found")
        })
        @DeleteExchange("/categories/delete/{code}")
        public ResponseEntity<?> deleteCategory(@PathVariable @NotNull(message = "Code is required") String code) {
                actionService.deleteCategory(code);
                Map<String, Object> response = Map.of("status", true, "message",
                                "Action category deleted successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @Operation(summary = "Restore Action Category", description = "Restores a deleted action category in the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Action category restored successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action category not found")
        })
        @PatchExchange("/categories/restore/{code}")
        public ResponseEntity<?> restoreCategory(@PathVariable @NotNull(message = "Code is required") String code) {
                actionService.restoreCategory(code);
                Map<String, Object> response = Map.of("status", true, "message",
                                "Action category restored successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @Operation(summary = "Create Action", description = "Creates a new action in the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Action created successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action not found")
        })
        @PostMapping("/create")
        public ResponseEntity<?> createAction(@RequestBody @Valid ActionRequest request) {
                actionService.createAction(request);
                Map<String, Object> response = Map.of("status", true, "message", "Action created successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @Operation(summary = "Get All Actions", description = "Retrieves all actions in the audit system")
        @ApiResponses(value = {
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Actions retrieved successfully"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Unauthorized"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "403", description = "Forbidden"),
                        @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "404", description = "Action not found")
        })
        @GetMapping("/get-all")
        public ResponseEntity<?> getAllActions(
                        @RequestParam(required = false) String[] category_codes,
                        @RequestParam(required = false, defaultValue = "false") boolean include_deleted_category,
                        @RequestParam(required = false, defaultValue = "false") boolean include_deleted) {
                List<ActionResponse> actions = actionService.getAllActions(include_deleted_category,
                                include_deleted, category_codes);
                Map<String, Object> response = Map.of("status", true,
                                "message", "audit actions fetched successfully",
                                "total_actions", actions.size(),
                                "data", actions);
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @PatchExchange("/edit/{code}")
        public ResponseEntity<?> editAction(@PathVariable @NotNull(message = "Code is required") String code,
                        @RequestBody @Valid ActionEditRequest request) {
                actionService.updateAction(code, request);
                Map<String, Object> response = Map.of("status", true, "message", "Action edited successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @DeleteMapping("/delete/{code}")
        public ResponseEntity<?> deleteAction(@PathVariable @NotNull(message = "Code is required") String code) {
                actionService.deleteAction(code);
                Map<String, Object> response = Map.of("status", true, "message", "Action deleted successfully");
                return ResponseEntity.ok(response);
        }

        @PreAuthorize("hasAnyRole('ROLE_SUPER_ADMIN','ROLE_ADMIN','ROLE_TEAM_MEMBER')")
        @PatchMapping("/restore/{code}")
        public ResponseEntity<?> restoreAction(@PathVariable @NotNull(message = "Code is required") String code) {
                actionService.restoreAction(code);
                Map<String, Object> response = Map.of("status", true, "message", "Action restored successfully");
                return ResponseEntity.ok(response);
        }
}

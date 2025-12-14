package com.example.authservice.services;

import java.util.Date;

import org.springframework.stereotype.Service;

import com.example.authservice.DTOS.ActionCategoryRequest;
import com.example.authservice.Entities.AuditActionCategoryEntity;
import com.example.authservice.repositories.ActionCategoryRepository;
import com.example.authservice.repositories.AuditActionRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ActionService {
    private final ActionCategoryRepository actionCategoryRepository;
    private final AuditActionRepository auditActionRepository;
    private final AuditService auditService;

    public void auditCategoryCreation(ActionCategoryRequest request) {
        log.info("Auditing creation of activity category with code: {}", request.getCode());
        if (isCategoryExists(request.getCode())) {
            log.warn("Activity category with code {} already exists. Skipping creation.", request.getCode());
            throw new CategoryAlreadyExistsException(
                    "Activity category with code " + request.getCode() + " already exists.");
        }
        AuditActionCategoryEntity category = AuditActionCategoryEntity.builder()
                .code(request.getCode())
                .title(request.getTitle())
                .description(request.getDescription())
                .created_at(new Date())
                .build();
        actionCategoryRepository.save(category);
        log.info("Created activity category with code: " + request.getCode());
    }

    boolean isCategoryExists(String code) {
        return actionCategoryRepository.existsById(code);
    }

    public static class CategoryAlreadyExistsException extends RuntimeException {
        public CategoryAlreadyExistsException(String message) {
            super(message);
        }
    }
}

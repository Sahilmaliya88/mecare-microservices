package com.example.authservice.services;

import java.util.Date;
import java.util.List;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import com.example.authservice.DTOS.ActionCategoryEditRequest;
import com.example.authservice.DTOS.ActionCategoryRequest;
import com.example.authservice.Entities.AuditActionCategoryEntity;
import com.example.authservice.repositories.ActionCategoryRepository;
import com.example.authservice.repositories.AuditActionRepository;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ActionService {
    private final ActionCategoryRepository actionCategoryRepository;
    private final AuditActionRepository auditActionRepository;
    private final AuditService auditService;

    @Transactional
    @CacheEvict(value = "audit-action-categories", allEntries = true)
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

    @Cacheable(value = "audit-action-categories", unless = "#include_deleted")
    public List<AuditActionCategoryEntity> getAllCategories(boolean include_deleted) {
        if (include_deleted) {
            return actionCategoryRepository.findAll();
        }
        return actionCategoryRepository.findAllWhereIsDeletedFalse();
    }

    @Transactional
    @CacheEvict(value = "audit-action-categories", allEntries = true)
    public void editCategory(ActionCategoryEditRequest request, String code) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Code is required");
        }
        AuditActionCategoryEntity category = actionCategoryRepository.findById(code)
                .orElseThrow(() -> new CategoryNotFoundException("Category with code " + code + " not exists!"));
        category.setTitle(request.getTitle());
        category.setDescription(request.getDescription());
        actionCategoryRepository.save(category);
    }

    @Transactional
    @CacheEvict(value = "audit-action-categories", allEntries = true)
    public void deleteCategory(String code) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Code is required");
        }
        AuditActionCategoryEntity category = actionCategoryRepository.findById(code)
                .orElseThrow(() -> new CategoryNotFoundException("Category with code " + code + " not exists!"));
        category.set_deleted(true);
        actionCategoryRepository.save(category);
    }

    public void restoreCategory(String code) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Code is required");
        }
        AuditActionCategoryEntity category = actionCategoryRepository.findById(code).orElseThrow(
                () -> new CategoryNotFoundException("Activity category with code " + code + " does not exist."));
        if (!category.is_deleted()) {
            throw new CategoryAlreadyExistsException("Activity category with code " + code + " is not deleted.");
        }
        category.set_deleted(false);
        actionCategoryRepository.save(category);
    }

    boolean isCategoryExists(String code) {
        return actionCategoryRepository.existsById(code);
    }

    public static class CategoryAlreadyExistsException extends RuntimeException {
        public CategoryAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class CategoryNotFoundException extends RuntimeException {
        public CategoryNotFoundException(String message) {
            super(message);
        }
    }
}

package com.mecare.authservice.services;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.mecare.authservice.DTOS.ActionCategoryEditRequest;
import com.mecare.authservice.DTOS.ActionCategoryRequest;
import com.mecare.authservice.DTOS.ActionEditRequest;
import com.mecare.authservice.DTOS.ActionRequest;
import com.mecare.authservice.DTOS.ActionResponse;
import com.mecare.authservice.entities.AuditActionCategoryEntity;
import com.mecare.authservice.entities.AuditActions;
import com.mecare.authservice.repositories.ActionCategoryRepository;
import com.mecare.authservice.repositories.AuditActionRepository;
import com.mecare.avro.AuditLog;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class ActionService {
    private final ActionCategoryRepository actionCategoryRepository;
    private final AuditActionRepository auditActionRepository;
    private final KafkaTemplate<String, AuditLog> kafkaTemplate;

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

    // @Cacheable(value = "audit-action-categories", unless = "#include_deleted")
    public List<AuditActionCategoryEntity> getAllCategories(boolean include_deleted) {
        AuditLog auditLog = AuditLog.newBuilder()
                .setId(UUID.randomUUID().toString())
                .setActorId("b2a6c9f1-5f4b-4c90-8e32-1d9b9b1a1111")
                .setActorType("USER")
                .setTargetId("a7c1f8d4-1c3b-42e6-b6aa-222222222222")
                .setTargetType("APPOINTMENT")
                .setActionTypeCode("CREATE")
                .setActionCategoryCode("APPOINTMENT_MANAGEMENT")
                .setImpersonatedUserId(null)
                .setPreviousData(null)
                .setNewData("{\"status\":\"CONFIRMED\"}")
                .setIpAddress("192.168.1.10")
                .setUserAgent("Mozilla/5.0")
                .setSourceDevice("WEB")
                .setCreatedAt(Instant.now())
                .build();
        kafkaTemplate.send("audit-events", "audit-action-categories-" + System.currentTimeMillis(), auditLog);
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

    @Transactional
    @CacheEvict(value = "audit-actions", allEntries = true)
    public void createAction(ActionRequest request) {
        if (request.getCategoryCode() == null || request.getCategoryCode().isBlank()) {
            throw new IllegalArgumentException("Category code is required");
        }
        if (isActionExists(request.getCode())) {
            throw new ActionAlreadyExistsException("Action with code " + request.getCode() + " already exists!");
        }
        AuditActionCategoryEntity category = actionCategoryRepository
                .findById(request.getCategoryCode())
                .orElseThrow(() -> new CategoryNotFoundException(
                        "Category with code " + request.getCategoryCode() + " not exists!"));
        if (category.is_deleted()) {
            throw new CategoryDeletedException("Category with code " + request.getCategoryCode() + " is deleted!");
        }
        AuditActions action = AuditActions.builder()
                .code(request.getCode())
                .title(request.getTitle())
                .description(request.getDescription())
                .category(category)
                .created_at(new Date())
                .build();
        auditActionRepository.save(action);

    }

    @Cacheable(value = "audit-actions", unless = "#include_deleted || #include_deleted_category || #categoryCodes != null")
    public List<ActionResponse> getAllActions(boolean include_deleted_category, boolean include_deleted,
            String[] categoryCodes) {
        return auditActionRepository.findAllActiveActions(categoryCodes, include_deleted_category, include_deleted);
    }

    @Transactional
    @CacheEvict(value = "audit-actions", allEntries = true)
    public void deleteAction(String code) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Action code is required");
        }
        AuditActions action = auditActionRepository.findById(code)
                .orElseThrow(() -> new ActionNotFoundException("Action with code " + code + " not found!"));
        action.set_deleted(true);
        auditActionRepository.save(action);
    }

    @Transactional
    @CacheEvict(value = "audit-actions", allEntries = true)
    public void restoreAction(String code) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Action code is required");
        }
        AuditActions action = auditActionRepository.findById(code)
                .orElseThrow(() -> new ActionNotFoundException("Action with code " + code + " not found!"));
        if (!action.is_deleted()) {
            throw new ActionNotDeletedException("Action with code " + code + " is not deleted.");
        }
        action.set_deleted(false);
        auditActionRepository.save(action);
    }

    @Transactional
    @CacheEvict(value = "audit-actions", allEntries = true)
    public void updateAction(String code, ActionEditRequest request) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("Action code is required");
        }
        AuditActions action = auditActionRepository.findById(code)
                .orElseThrow(() -> new ActionNotFoundException("Action with code " + code + " not found!"));
        if (action.is_deleted()) {
            throw new ActionNotDeletedException("Action with code " + code + " is deleted.");
        }
        Optional.ofNullable(request.getTitle()).ifPresent(action::setTitle);
        Optional.ofNullable(request.getDescription()).ifPresent(action::setDescription);
        auditActionRepository.save(action);
    }

    public static class ActionNotFoundException extends RuntimeException {
        public ActionNotFoundException(String message) {
            super(message);
        }
    }

    public static class ActionNotDeletedException extends RuntimeException {
        public ActionNotDeletedException(String message) {
            super(message);
        }
    }

    boolean isCategoryExists(String code) {
        return actionCategoryRepository.existsById(code);
    }

    boolean isActionExists(String code) {
        return auditActionRepository.existsById(code);
    }

    public static class CategoryAlreadyExistsException extends RuntimeException {
        public CategoryAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class CategoryDeletedException extends RuntimeException {
        public CategoryDeletedException(String message) {
            super(message);
        }
    }

    public static class ActionAlreadyExistsException extends RuntimeException {
        public ActionAlreadyExistsException(String message) {
            super(message);
        }
    }

    public static class CategoryNotFoundException extends RuntimeException {
        public CategoryNotFoundException(String message) {
            super(message);
        }
    }
}

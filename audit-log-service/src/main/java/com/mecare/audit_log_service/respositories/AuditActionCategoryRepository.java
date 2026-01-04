package com.mecare.audit_log_service.respositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.audit_log_service.entities.AuditActionCategoryEntity;

public interface AuditActionCategoryRepository extends JpaRepository<AuditActionCategoryEntity, String> {

}

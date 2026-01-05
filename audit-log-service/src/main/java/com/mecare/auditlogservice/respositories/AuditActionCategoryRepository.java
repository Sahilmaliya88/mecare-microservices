package com.mecare.auditlogservice.respositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.auditlogservice.entities.AuditActionCategoryEntity;

public interface AuditActionCategoryRepository extends JpaRepository<AuditActionCategoryEntity, String> {

}

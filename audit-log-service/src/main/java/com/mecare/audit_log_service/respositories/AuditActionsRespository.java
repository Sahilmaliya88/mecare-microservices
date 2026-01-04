package com.mecare.audit_log_service.respositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.audit_log_service.entities.AuditActions;

public interface AuditActionsRespository extends JpaRepository<AuditActions, String> {

}

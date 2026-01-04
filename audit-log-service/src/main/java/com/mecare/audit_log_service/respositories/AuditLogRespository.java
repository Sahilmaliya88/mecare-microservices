package com.mecare.audit_log_service.respositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.audit_log_service.entities.AuditLogEntity;

public interface AuditLogRespository extends JpaRepository<AuditLogEntity, UUID> {

}

package com.mecare.auditlogservice.respositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.auditlogservice.entities.AuditLogEntity;

public interface AuditLogRespository extends JpaRepository<AuditLogEntity, UUID> {

}

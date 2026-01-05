package com.mecare.auditlogservice.respositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mecare.auditlogservice.entities.AuditActions;

public interface AuditActionsRespository extends JpaRepository<AuditActions, String> {

}

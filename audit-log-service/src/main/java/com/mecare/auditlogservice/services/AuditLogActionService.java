package com.mecare.auditlogservice.services;

import com.mecare.auditlogservice.entities.AuditActions;
import com.mecare.auditlogservice.respositories.AuditActionsRespository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuditLogActionService {
    private final AuditActionsRespository auditActionsRespository;

    @Cacheable(
            value = "audit-actions",
            key = "#actionTypeCode"
    )
    public AuditActions getAuditActions(String actionTypeCode) {
        return auditActionsRespository.findById(actionTypeCode)
                .orElseThrow(() -> new RuntimeException("Audit action not found"));
    }


}

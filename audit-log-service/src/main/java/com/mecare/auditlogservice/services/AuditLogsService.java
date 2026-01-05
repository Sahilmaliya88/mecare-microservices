package com.mecare.auditlogservice.services;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import com.mecare.auditlogservice.entities.AuditLogEntity;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AuditLogsService {
    @KafkaListener(topics = "audit-events", groupId = "audit-log-service")
    public void saveAuditLog(AuditLogEntity auditLogEntity, Acknowledgment acknowledgment) {
        log.info("Audit log saved: {}", auditLogEntity);
        acknowledgment.acknowledge();
    }
}

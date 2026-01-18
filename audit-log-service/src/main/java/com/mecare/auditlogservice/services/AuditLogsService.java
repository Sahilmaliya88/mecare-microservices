package com.mecare.auditlogservice.services;

import java.sql.Date;
import java.time.Duration;
import java.util.UUID;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mecare.auditlogservice.entities.AuditActions;
import com.mecare.auditlogservice.entities.AuditLogEntity;
import com.mecare.auditlogservice.respositories.AuditActionsRespository;
import com.mecare.auditlogservice.respositories.AuditLogRespository;
import com.mecare.avro.AuditLog;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogsService {
    private final AuditLogRespository auditLogRepository;
    private final AuditActionsRespository auditActionsRespository;
    private final ObjectMapper objectMapper;
    private final AuditLogActionService auditLogActionService;
    @KafkaListener(topics = "audit-events", groupId = "audit-log-service")
    public void saveAuditLog(ConsumerRecord<String, AuditLog> record, Acknowledgment acknowledgment) {
        try {
            AuditLog auditLog = record.value();
            JsonNode newData = auditLog.getNewData() == null ? null : objectMapper.readTree(auditLog.getNewData());
            JsonNode previousData = auditLog.getPreviousData() == null ? null
                    : objectMapper.readTree(auditLog.getPreviousData());
            AuditActions actionType = auditLogActionService.getAuditActions(auditLog.getActionTypeCode());
            UUID impersonatedUserId = auditLog.getImpersonatedUserId() == null ? null
                    : UUID.fromString(auditLog.getImpersonatedUserId());
            log.info("Audit log saved: {}",
                    auditLog.getImpersonatedUserId() == null ? "No impersonated user"
                            : auditLog.getImpersonatedUserId());
            AuditLogEntity auditLogEntity = AuditLogEntity.builder()
                    .actor_id(UUID.fromString(auditLog.getActorId()))
                    .actor_type(auditLog.getActorType())
                    .target_id(UUID.fromString(auditLog.getTargetId()))
                    .target_type(auditLog.getTargetType())
                    .created_at(Date.from(auditLog.getCreatedAt()))
                    .impersonated_user_id(impersonatedUserId)
                    .new_data(newData)
                    .previous_data(previousData)
                    .ip_address(auditLog.getIpAddress())
                    .user_agent(auditLog.getUserAgent())
                    .source_device(auditLog.getSourceDevice())
                    .action_type(actionType)
                    .action_category(actionType.getCategory())
                    .build();
            auditLogRepository.save(auditLogEntity);
            acknowledgment.acknowledge();
        } catch (Exception e) {
            log.error("Error saving audit log: {}", e.getMessage());
            acknowledgment.nack(Duration.ofSeconds(10));
        }
    }

}

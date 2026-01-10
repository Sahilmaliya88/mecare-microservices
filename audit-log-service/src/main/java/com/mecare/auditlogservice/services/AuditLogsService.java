package com.mecare.auditlogservice.services;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AuditLogsService {
    @KafkaListener(topics = "audit-events", groupId = "audit-log-service")
    public void saveAuditLog(ConsumerRecord<String, Object> record, Acknowledgment acknowledgment) {
        log.info("Audit log saved: {}", record.value().getClass().getName());
        acknowledgment.acknowledge();
    }
}

package com.example.authservice.services;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import com.example.authservice.DTOS.AuditEvent;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    @KafkaListener(topics = "audit-events", groupId = "auth-service")
    public void createAuditEvent(AuditEvent auditEvent, Acknowledgment ack) {
        log.info("Audit event received: {}", auditEvent.getType());
        ack.acknowledge();
    }
}

package com.mecare.authservice.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mecare.avro.AuditLog;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {
    private final KafkaTemplate<String,AuditLog> kafkaTemplate;
    private  final ObjectMapper objectMapper;

    /**
     * @param actor_id - action performer's id
     * @param actor_type - role of actor
     * @param target_id - target user's id
     * @param target_type - target user's role
     * @param action_type_code - Action Type code
     * @param action_category_code - action category
     * @param created_at - action performed time
     * @param impersonate_user_id - if user was impersonated by someone then id
     * @param new_data - map of updated data
     * @param prev_data - map of old data
     * @param ip_address - ip address of performer
     * @param user_agent - user agent
     * @param  source_device - performers source device
     */
    public void sendAuditLog(
            UUID actor_id,
            String actor_type,
            UUID target_id,
            String target_type,
            String action_type_code,
            String action_category_code,
            Instant created_at,
            String impersonate_user_id,
            Map new_data,
            Map prev_data,
            String ip_address,
            String user_agent,
            String source_device
    ) throws JsonProcessingException {
        String parsedPrevData = prev_data == null ? null : objectMapper.writeValueAsString(prev_data);
        String parseNewData = new_data == null ? null :objectMapper.writeValueAsString(new_data);
        AuditLog auditLog = AuditLog.newBuilder()
                .setActorId(actor_id.toString())
                .setActorType(actor_type)
                .setTargetId(target_id.toString())
                .setTargetType(target_type)
                .setActionCategoryCode(action_category_code)
                .setActionTypeCode(action_type_code)
                .setCreatedAt(created_at)
                .setImpersonatedUserId(impersonate_user_id)
                .setPreviousData(parsedPrevData)
                .setNewData(parseNewData)
                .setSourceDevice(source_device)
                .setUserAgent(user_agent)
                .setIpAddress(ip_address)
                .build();
        kafkaTemplate.send("audit-events",auditLog)  ;
    }
}

package com.mecare.authservice.services;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mecare.authservice.Entities.UserEntity;
import com.mecare.authservice.utils.exceptions.TokenExpiredException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JWTService {
    @Value("${spring.datasource.jwt-secret}")
    private String jwtSecret;

    public String getJwtToken(UserEntity userEntity) throws JsonProcessingException {
        if (userEntity.getEmail() == null || userEntity.getRole() == null || userEntity.getIs_verified() == null
                || userEntity.getToken_version() == null) {
            throw new NullPointerException("Missing token data from generate token");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        Date expiryDate = new Date(new Date().getTime() + 7 * 24 * 60 * 60 * 1000);
        Map<String, Object> jwtContent = Map.of(
                "id", userEntity.getId().toString(),
                "email", userEntity.getEmail(),
                "verified", userEntity.getIs_verified(),
                "role", userEntity.getRole().toString(),
                "version", userEntity.getToken_version());
        String subject = objectMapper.writeValueAsString(jwtContent);
        return Jwts.builder()
                .subject(subject)
                .expiration(expiryDate)
                .issuedAt(new Date())
                .signWith(jwtSignInKey())
                .compact();

    }

    public String getJwtTokenForSession(UserEntity userEntity, String deviceId, String tokenVersion)
            throws JsonProcessingException {
        if (userEntity.getEmail() == null || userEntity.getRole() == null || userEntity.getIs_verified() == null
                || tokenVersion == null || deviceId == null) {
            throw new NullPointerException("Missing token data from generate token");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        Date expiryDate = new Date(new Date().getTime() + 7 * 24 * 60 * 60 * 1000);
        Map<String, Object> jwtContent = Map.of(
                "id", userEntity.getId().toString(),
                "email", userEntity.getEmail(),
                "verified", userEntity.getIs_verified(),
                "role", userEntity.getRole().toString(),
                "version", tokenVersion,
                "device_id", deviceId);
        String subject = objectMapper.writeValueAsString(jwtContent);
        return Jwts.builder()
                .subject(subject)
                .expiration(expiryDate)
                .issuedAt(new Date())
                .signWith(jwtSignInKey())
                .compact();

    }

    public String getJwtToken(UserEntity tagetUser, String email, String version, String deviceId)
            throws JsonProcessingException {
        if (tagetUser.getEmail() == null || tagetUser.getRole() == null || tagetUser.getIs_verified() == null
                || email == null || version == null) {
            throw new NullPointerException("Missing token data from generate token");
        }
        ObjectMapper objectMapper = new ObjectMapper();
        Date expiryDate = new Date(new Date().getTime() + 7 * 24 * 60 * 60 * 1000);
        Map<String, Object> jwtContent = Map.of(
                "impersonate", true,
                "id", tagetUser.getId().toString(),
                "email", tagetUser.getEmail(),
                "verified", tagetUser.getIs_verified(),
                "role", tagetUser.getRole().toString(),
                "version", version,
                "device_id", deviceId,
                "impersonate_by", email);
        String subject = objectMapper.writeValueAsString(jwtContent);
        return Jwts.builder()
                .subject(subject)
                .expiration(expiryDate)
                .issuedAt(new Date())
                .signWith(jwtSignInKey())
                .compact();
    }

    public Map<String, Object> getJwtClaims(String jwtToken) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Claims claims = Jwts.parser()
                .verifyWith(jwtSignInKey())
                .build()
                .parseSignedClaims(jwtToken)
                .getPayload();
        if (claims.getExpiration().before(new Date())) {
            throw new TokenExpiredException("Token expired please login again");
        }
        String payload = claims.getSubject();
        return objectMapper.readValue(payload, Map.class);
    }

    private SecretKey jwtSignInKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }
}

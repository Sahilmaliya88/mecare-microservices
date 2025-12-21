package com.mecare.apigateway.services;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtService {
    @Value("${spring.environments.jwt-secret}")
    private String jwtKey;

    public Map getClaims(String jwtToken) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        // get claims
        Claims claims = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(jwtToken).getPayload();
        if (claims == null)
            return null;
        if (claims.getExpiration().before(new Date()))
            return null;
        String tokenSubject = claims.getSubject();
        return mapper.readValue(tokenSubject, Map.class);
    }

    private SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(jwtKey.getBytes());
    }
}

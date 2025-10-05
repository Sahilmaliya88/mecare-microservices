package com.example.apigateway.Configs;
import com.example.apigateway.services.JwtService;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Global filter configuration for validating JWT tokens in incoming requests.
 * This filter extracts and validates the JWT from the Authorization header,
 * retrieves claims, and logs relevant information for debugging and monitoring.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class JWTFilter implements Ordered {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String EMAIL_CLAIM_KEY = "email";
    private static final String VERSION_KEY_PREFIX = "version-";
    private static final String VERSION_CLAIM_KEY = "version";
    private static final String ROLE_CLAIM_KEY ="role";
    private static final String VERIFIED_CLAIM_KEY = "verified";
    private static final String EMAIL_HEADER_KEY= "x-user-email";
    private static final String ROLE_HEADER_KEY = "x-user-role";
    private static final String VERIFIED_HEADER_KEY = "x-user-verified";
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtService jwtService;

    /**
     * Configures a global filter to process JWT tokens in the Authorization header.
     *
     * @return A GlobalFilter that processes incoming requests.
     */
    @Bean
    public GlobalFilter jwtFilter() {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            Optional<String> jwt = extractJwtFromHeader(request.getHeaders());

            if (jwt.isEmpty()) {
                log.debug("No Authorization header or invalid format found in request to {}", request.getURI());
                return chain.filter(exchange);
            }

            try {
                Map<String, Object> claims = jwtService.getClaims(jwt.get());
                String email = (String) claims.get(EMAIL_CLAIM_KEY);
                String version = (String) claims.get(VERSION_CLAIM_KEY);
                String role = (String) claims.get(ROLE_CLAIM_KEY);
                System.out.println(role);
                Boolean verified = (Boolean) claims.get(VERIFIED_CLAIM_KEY);
                if (email == null || verified == null || role == null || version == null) {
                    return handleErrorResponse(exchange,HttpStatus.BAD_REQUEST,"Token is corrupted");
                } else {
                    String storedVersionRaw = extractTokenVersionFromRedis(email);
                    String storedVersion;
                    int dashIndex = storedVersionRaw.indexOf("-");
                    if (dashIndex != -1 && dashIndex == storedVersionRaw.length()-2) {
                        storedVersion = storedVersionRaw.substring(0, dashIndex);
                        int rank = Integer.parseInt(storedVersionRaw.substring(dashIndex+1));
                        role = getUserRoleByRange(rank);
                    } else {
                        storedVersion = storedVersionRaw; // or handle differently if no "-" exists
                    }

                    if(Objects.equals(storedVersion,version)){
                        log.info(version);
                        ServerHttpRequest modifiedRequest = request.mutate()
                                .header(EMAIL_HEADER_KEY,email)
                                .header(ROLE_HEADER_KEY,role)
                                .header(VERIFIED_HEADER_KEY,Boolean.toString(verified))
                                .build();
                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    }
                }
            } catch (JsonProcessingException e) {
                log.error("Failed to parse JWT for request to {}: {}", request.getURI(), e.getMessage());
                String errorMessage = "Failed to parse JWT for request to " + request.getURI()+": "+e.getMessage();
                return handleErrorResponse(exchange,HttpStatus.INTERNAL_SERVER_ERROR,errorMessage);
            } catch (Exception e) {
                log.error("Unexpected error while processing JWT for request to {}: {}", request.getURI(), e.getMessage());
                String errorMessage = "Unexpected error while processing JWT for request to " + request.getURI()+": "+e.getMessage();
                return handleErrorResponse(exchange,HttpStatus.INTERNAL_SERVER_ERROR,errorMessage);
            }

            return chain.filter(exchange);
        };
    }

    /**
     * Extracts the JWT token from the Authorization header, if present and properly formatted.
     *
     * @param headers The HTTP headers from the request.
     * @return An Optional containing the JWT token, or empty if not found or invalid.
     */
    private Optional<String> extractJwtFromHeader(HttpHeaders headers) {
        List<String> authorizationHeaders = headers.get(HttpHeaders.AUTHORIZATION);
        if (authorizationHeaders == null || authorizationHeaders.isEmpty()) {
            return Optional.empty();
        }
        String authHeader = authorizationHeaders.getFirst();
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }
        return Optional.of(authHeader.substring(BEARER_PREFIX.length()));
    }

    /**
     * Fetched the token version from redis, using email with VERSION_KEY_PREFIX
     * return token version if present in redis else returns null
     */
    private String extractTokenVersionFromRedis(String email){
        try{
            String tokenVersionKey =VERSION_KEY_PREFIX+email;
            return redisTemplate.opsForValue().get(tokenVersionKey);
        } catch (RedisConnectionFailureException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
    /**
     * Construct the error response and terminates filter chain
     * @param exchange The ServerWebExchange to modify
     * @param statusCode The HttpStatus code to send with response
     * @param errorMessage the Error message to send
     *
     * @return A Mono indication the completion for error response
     */
    private Mono<Void> handleErrorResponse(ServerWebExchange exchange, HttpStatus statusCode,String errorMessage){
        exchange.getResponse().setStatusCode(statusCode);
        exchange.getResponse().getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        String errorBody = String.format("{\"error\": \"%s\"}", errorMessage);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(errorBody.getBytes())));
    }
    private String getUserRoleByRange(int rank){
       List<String> roles = List.of("SUPER_ADMIN","ADMIN","TEAM_MEMBER","TEAM_DOCTOR","DOCTOR","USER");
       return roles.get(rank);
    }
    /**
     * Defines the order of this filter in the Spring Cloud Gateway filter chain.
     * Set to -1 to ensure this filter runs early in the chain.
     * @return The filter order.
     */
    @Override
    public int getOrder() {
        return -1;
    }
}
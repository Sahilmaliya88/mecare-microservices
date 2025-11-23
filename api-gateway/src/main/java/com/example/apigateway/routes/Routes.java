package com.example.apigateway.routes;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Routes {
        @Bean
        public RouteLocator routeLocator(RouteLocatorBuilder builder) {
                return builder.routes()
                                .route("auth-service", r -> r.path("/api/v1/auth/**")
                                                .uri("lb://auth-service"))
                                .route("user-service", r -> r.path("/api/v1/user/**")
                                                .uri("lb://auth-service"))
                                .route("auth-service-docs", p -> p.path("/aggregate/auth-service/v3/api-docs")
                                                .filters(f -> f.rewritePath("/aggregate/auth-service/v3/api-docs",
                                                                "/v3/api-docs"))
                                                .uri("lb://auth-service"))
                                .build();
        }
}

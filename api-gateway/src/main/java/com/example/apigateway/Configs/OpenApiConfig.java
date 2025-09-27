package com.example.apigateway.Configs;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI openAPI(){
        return new OpenAPI()
                .info(new Info().version("1.0.0").description("api gateway for all microservices").title("API-GATEWAY"))
                .servers(List.of(new Server().description("Local Server").url("http://localhost:8080")));
    }
}

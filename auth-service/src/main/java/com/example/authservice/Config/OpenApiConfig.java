package com.example.authservice.Config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.util.List;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI customOpenApi(){
        return new OpenAPI()
                .servers(
                        List.of(new Server().description("Api gateway for microservices").url("http://localhost:8080/"))
                )
                .info(new Info().title("Auth Service").description("Apis for auth service").version("1.0.0"))
                .addSecurityItem(new SecurityRequirement().addList("HeaderAuth"))
                .openapi("3.0.1")
                .components(new Components()
                        .addSecuritySchemes("HeaderAuth",new SecurityScheme().type(SecurityScheme.Type.HTTP)
                                .scheme("Bearer").bearerFormat("JWT")
                        ));
    }
}

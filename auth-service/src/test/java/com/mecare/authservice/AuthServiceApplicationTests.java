package com.mecare.authservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootTest(classes = AuthServiceApplication.class)
@EnableDiscoveryClient
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}

package com.mecare.authservice.Config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import io.imagekit.sdk.ImageKit;
import jakarta.annotation.PostConstruct;

@Configuration
public class ImagekitConfig {

    @Value("${spring.environments.image-kit.publicKey}")
    private String publicKey;
    @Value("${spring.environments.image-kit.privateKey}")
    private String privateKey;
    @Value("${spring.environments.image-kit.urlEndpoint}")
    private String urlEndpoint;

    @PostConstruct
    public void init() {
        ImageKit imageKit = ImageKit.getInstance();
        io.imagekit.sdk.config.Configuration config = new io.imagekit.sdk.config.Configuration();
        config.setPublicKey(publicKey);
        config.setPrivateKey(privateKey);
        config.setUrlEndpoint(urlEndpoint);
        imageKit.setConfig(config);
    }
}

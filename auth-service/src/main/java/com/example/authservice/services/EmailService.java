package com.example.authservice.services;

import com.example.authservice.Entities.UserEntity;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

@Slf4j
@Service
public class EmailService {
    @Autowired
    private JavaMailSender javaMailSender;
    @Autowired
    private TemplateEngine templateEngine;
    @Value("${spring.environments.app-url}")
    private String appUrl;
    /**
     * A Asynchronize function which sends welcome email to particular user with otp
     */
    @Async
    public void SendWelcome(UserEntity user){
        try {
            Context context = new Context();
            context.setVariable("email",user.getEmail());
            context.setVariable("otp",user.getVerification_code());
            String parsedTemplate = templateEngine.process("Welcome",context);
            MimeMessage message= javaMailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message,true);
            helper.setFrom("mecare@support.com");
            helper.setTo(user.getEmail());
            helper.setText(parsedTemplate,true);
            helper.setSubject("Welcome Message");
            javaMailSender.send(message);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }
}

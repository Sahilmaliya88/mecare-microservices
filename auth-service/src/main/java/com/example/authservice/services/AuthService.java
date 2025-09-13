package com.example.authservice.services;

import com.example.authservice.DTOS.RegisterUserRequest;
import com.example.authservice.DTOS.VerifyRequest;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.utils.exceptions.Unauthorize;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.redis.core.RedisTemplate;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;


@Slf4j
@Service
public class AuthService {
    private static final String NUMBERS = "0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JWTService jwtService;
    private final RedisTemplate<String,String> redisTemplate;
    private final AuthenticationManager authenticationManager;
    public AuthService(UserRepository userRepository, EmailService emailService, JWTService jwtService, RedisTemplate<String,String> redisTemplate,AuthenticationManager authenticationManager){
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
    }
    public String registerUser(RegisterUserRequest registerUserRequest) throws JsonProcessingException {
        //create hash of password
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
        String hashedPassword = passwordEncoder.encode(registerUserRequest.getPassword());
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        String otp = generateOtp(6);
        Date verificationCodeExpiresAt = new Date(new Date().getTime()+15*60*1000);
        //create user
        UserEntity newUser =UserEntity.builder()
                .email(registerUserRequest.getEmail())
                .password(hashedPassword)
                .token_version(tokenVersion)
                .created_at(new Date())
                .verification_code_expires_at(verificationCodeExpiresAt)
                .verification_code(otp)

                .build();
        //send verification code
        userRepository.save(newUser);
        //generate token and set version to redis
        redisTemplate.opsForValue().set("version-"+newUser.getEmail(),newUser.getToken_version());
        String jwtToken = generateJwt(newUser);
        //save user
        emailService.SendWelcome(newUser);
        //return response
        return jwtToken;
    }
    public String verifyUser(VerifyRequest verifyRequest) throws JsonProcessingException {
        UserEntity userEntity = userRepository.findByEmail(verifyRequest.getEmail())
                .orElseThrow(()->new Unauthorize("User not found with this email"));
        if(!Objects.equals(userEntity.getVerification_code(), verifyRequest.getOtp())) throw new Unauthorize("Invalid Otp", HttpStatus.UNAUTHORIZED);
        if(userEntity.getVerification_code_expires_at().before(new Date())) throw new Unauthorize("Otp expired!.please request new one",HttpStatus.BAD_REQUEST);
        userEntity.setIs_verified(true);
        userEntity.setVerification_code(null);
        userEntity.setVerification_code_expires_at(null);
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        redisTemplate.opsForValue().set("version-"+userEntity.getEmail(),tokenVersion);
        userEntity.setToken_version(tokenVersion);
        userRepository.save(userEntity);
        return jwtService.getJwtToken(userEntity);
    }
    public String loginUser(RegisterUserRequest registerUserRequest) throws JsonProcessingException {
         Authentication authentication= authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(registerUserRequest.getEmail(),registerUserRequest.getPassword()));
         if(!authentication.isAuthenticated()) throw new Unauthorize("Invalid credentials!");
         UserEntity userEntity = userRepository.findByEmail(registerUserRequest.getEmail())
                 .orElseThrow(()->new Unauthorize("User not found!"));
         String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
         userEntity.setToken_version(tokenVersion);
         userRepository.save(userEntity);
         redisTemplate.opsForValue().set("version-"+userEntity.getEmail(),tokenVersion);
         return generateJwt(userEntity);
    }
    private String generateJwt(UserEntity userEntity) throws JsonProcessingException {
        return jwtService.getJwtToken(userEntity);
    }
    private String generateOtp(int size) {
        StringBuilder otp = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
            int index = RANDOM.nextInt(NUMBERS.length());
            otp.append(NUMBERS.charAt(index));
        }
        return otp.toString();
    }
}

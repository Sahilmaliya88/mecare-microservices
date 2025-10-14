package com.example.authservice.services;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

import com.example.authservice.DTOS.ChangePasswordRequest;
import com.example.authservice.DTOS.ChangeUserRoleRequest;
import com.example.authservice.DTOS.GoogleUserProfileResponse;
import com.example.authservice.DTOS.PaginationResponse;
import com.example.authservice.DTOS.RegisterUserRequest;
import com.example.authservice.DTOS.ResetPasswordRequest;
import com.example.authservice.DTOS.SocialLoginRequest;
import com.example.authservice.DTOS.UploadCsvRequest;
import com.example.authservice.DTOS.UsersResponse;
import com.example.authservice.DTOS.VerifyRequest;
import com.example.authservice.Entities.LoginSessionEntity;
import com.example.authservice.Entities.UserEntity;
import com.example.authservice.repositories.SessionRepository;
import com.example.authservice.repositories.UserRepository;
import com.example.authservice.utils.DeviceInfo;
import com.example.authservice.utils.LoginProviders;
import com.example.authservice.utils.UserRoles;
import com.example.authservice.utils.exceptions.Unauthorize;
import com.fasterxml.jackson.core.JsonProcessingException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthService {
    private static final String NUMBERS = "0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRY_MINUTES = 15;
    private static final String USER_EMAIL_HEADER = "x-user-email";
    private static final String VERSION_PREFIX = "version-";
    private static final String IMPERSONATE_PREFIX = "impersonate-";
    private static final String IMPERSONATE_BY = "x-user-impersonate_by";
    private static final String IMPERSONATE = "x-user-impersonate";
    private static final String DEVICE_ID_HEADER = "x-device-id";
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final JWTService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<String, Object> redisTemplate;
    private final AuthenticationManager authenticationManager;
    private final RestTemplate restTemplate;
    private final SessionRepository sessionRepository;

    public AuthService(UserRepository userRepository, EmailService emailService, JWTService jwtService,
            PasswordEncoder passwordEncoder, RedisTemplate<String, Object> redisTemplate,
            AuthenticationManager authenticationManager, RestTemplate restTemplate,
            SessionRepository sessionRepository) {
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
        this.authenticationManager = authenticationManager;
        this.restTemplate = restTemplate;
        this.sessionRepository = sessionRepository;
    }

    public String registerUser(RegisterUserRequest registerUserRequest, HttpServletRequest request)
            throws JsonProcessingException {
        String hashedPassword = passwordEncoder.encode(registerUserRequest.getPassword());
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        String otp = generateOtp(6);
        String ipAddr = getClientIp(request);

        DeviceInfo deviceInfo = registerUserRequest.getDeviceInfo();
        log.info("Register attempt from IP: {}, Device: {}, OS: {}, Browser: {}, User-Agent: {}",
                ipAddr,
                deviceInfo.getDeviceId(),
                deviceInfo.getOs(),
                deviceInfo.getBrowser(),
                deviceInfo.getUserAgent());
        Date verificationCodeExpiresAt = new Date(new Date().getTime() + 15 * 60 * 1000);
        UserEntity newUser = userRepository.save(UserEntity.builder()
                .email(registerUserRequest.getEmail())
                .password(hashedPassword)
                .created_at(new Date())
                .verification_code_expires_at(verificationCodeExpiresAt)
                .verification_code(otp)
                .build());
        // save login session
        LoginSessionEntity loginSession = LoginSessionEntity.builder()
                .ipAddress(ipAddr)
                .user(newUser)
                .deviceId(deviceInfo.getDeviceId())
                .deviceType(deviceInfo.getDeviceType())
                .os(deviceInfo.getOs())
                .browser(deviceInfo.getBrowser())
                .userAgent(deviceInfo.getUserAgent())
                .lastUsedAt(new Date())
                .isActive(true)
                .tokenVersion(tokenVersion)
                .build();
        sessionRepository.save(loginSession);
        // generate token and set version to redis
        redisTemplate.opsForHash().put(VERSION_PREFIX + newUser.getId(), deviceInfo.getDeviceId(),
                tokenVersion);
        String jwtToken = jwtService.getJwtTokenForSession(newUser, deviceInfo.getDeviceId(), tokenVersion);
        // save user
        emailService.sendWelcomeEmail(newUser);
        // return response
        return jwtToken;
    }

    public String verifyUser(VerifyRequest verifyRequest, HttpServletRequest request) throws JsonProcessingException {
        UserEntity userEntity = userRepository.findByEmail(verifyRequest.getEmail())
                .orElseThrow(() -> new Unauthorize("User not found with this email"));
        if (!Objects.equals(userEntity.getVerification_code(), verifyRequest.getOtp()))
            throw new Unauthorize("Invalid Otp", HttpStatus.UNAUTHORIZED);
        if (userEntity.getVerification_code_expires_at().before(new Date()))
            throw new Unauthorize("Otp expired!.please request new one", HttpStatus.BAD_REQUEST);
        userEntity.setIs_verified(true);
        userEntity.setVerification_code(null);
        userEntity.setVerification_code_expires_at(null);

        LoginSessionEntity loginSession = sessionRepository.findByUserAndDeviceIdAndIsActive(userEntity,
                verifyRequest.getDeviceId(), true)
                .orElseThrow(() -> new Unauthorize("No active session found for this device Please login again",
                        HttpStatus.UNAUTHORIZED));
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        LoginSessionEntity session = LoginSessionEntity.builder()
                .user(userEntity)
                .deviceId(verifyRequest.getDeviceId())
                .deviceType(loginSession.getDeviceType())
                .os(loginSession.getOs())
                .browser(loginSession.getBrowser())
                .userAgent(loginSession.getUserAgent())
                .ipAddress(getClientIp(request))
                .isActive(true)
                .tokenVersion(tokenVersion)
                .lastUsedAt(new Date())
                .build();
        sessionRepository.deleteAllByUser(userEntity);
        sessionRepository.save(session);
        redisTemplate.delete(VERSION_PREFIX + userEntity.getId());
        redisTemplate.opsForHash().put(VERSION_PREFIX + userEntity.getId(), session.getDeviceId(),
                tokenVersion);
        userRepository.save(userEntity);
        return jwtService.getJwtTokenForSession(userEntity, verifyRequest.getDeviceId(), tokenVersion);
    }

    public String loginUser(RegisterUserRequest registerUserRequest, HttpServletRequest request)
            throws JsonProcessingException {

        // Authenticate credentials
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        registerUserRequest.getEmail(), registerUserRequest.getPassword()));

        // Fetch user
        UserEntity userEntity = userRepository.findByEmail(registerUserRequest.getEmail())
                .orElseThrow(() -> new Unauthorize("User not found!"));

        // Check login provider
        if (userEntity.getProvider() != LoginProviders.EMAIL) {
            throw new InvalidLoginTypeException("Please login through " + userEntity.getProvider());
        }

        // IP + Device
        String ipAddress = getClientIp(request);
        DeviceInfo deviceInfo = registerUserRequest.getDeviceInfo();
        log.info("Login attempt from IP: {}, Device: {}, OS: {}, Browser: {}, User-Agent: {}",
                ipAddress,
                deviceInfo.getDeviceId(),
                deviceInfo.getOs(),
                deviceInfo.getBrowser(),
                deviceInfo.getUserAgent());

        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        List<LoginSessionEntity> sessions = userEntity.getLoginSessions();
        if (sessions == null)
            sessions = new ArrayList<>();

        Optional<LoginSessionEntity> existingSessionOpt = sessions.stream()
                .filter(s -> s.getDeviceId().equals(deviceInfo.getDeviceId()))
                .findFirst();
        if (existingSessionOpt.isEmpty()) {
            LoginSessionEntity newSession = LoginSessionEntity.builder()
                    .ipAddress(ipAddress)
                    .user(userEntity)
                    .deviceId(deviceInfo.getDeviceId())
                    .deviceType(deviceInfo.getDeviceType())
                    .os(deviceInfo.getOs())
                    .browser(deviceInfo.getBrowser())
                    .userAgent(deviceInfo.getUserAgent())
                    .lastUsedAt(new Date())
                    .isActive(true)
                    .tokenVersion(tokenVersion)
                    .build();
            sessionRepository.save(newSession);
        } else {
            LoginSessionEntity session = existingSessionOpt.get();
            session.setIpAddress(ipAddress);
            session.setLastUsedAt(new Date());
            session.setTokenVersion(tokenVersion);
            session.setIsActive(true);
            sessionRepository.save(session);
        }

        // Save in Redis
        redisTemplate.opsForHash().put(
                VERSION_PREFIX + userEntity.getId(), deviceInfo.getDeviceId(),
                tokenVersion);

        return jwtService.getJwtTokenForSession(userEntity, deviceInfo.getDeviceId(), tokenVersion);
    }

    /**
     * Retrieves the authenticated user's details from the security context.
     *
     * @return the {@link UserEntity} associated with the authenticated user's email
     * @throws Unauthorize if the user is not authenticated or the email is invalid
     */
    public UserEntity getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()
                || authentication.getPrincipal() instanceof AnonymousAuthenticationToken) {
            throw new Unauthorize("User must be logged in to access this resource");
        }

        String email = authentication.getName();
        log.info("is authenticated {}", authentication.isAuthenticated());
        if (email == null || email.isBlank()) {
            throw new Unauthorize("Invalid authentication details: email not found");
        }
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new Unauthorize("No user found with email: " + email));
    }

    /**
     * Send verification code if user is not verified
     * throws Unauthorize if the user is not authenticated or the email is invalid
     * also can throw mail error
     */
    public void sendVerificationCode() {
        UserEntity user = getAuthenticatedUser();
        // Generate OTP and set expiration
        if (user.getIs_verified()) {
            throw new AlreadyVerifiedException("User is already verified");
        }
        String verificationCode = generateOtp(OTP_LENGTH);
        Instant expiryTime = Instant.now().plus(OTP_EXPIRY_MINUTES, ChronoUnit.MINUTES);
        // Update user entity
        user.setVerification_code(verificationCode);
        user.setVerification_code_expires_at(Date.from(expiryTime));
        try {
            userRepository.save(user);
            log.info("Saved verification code for user {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to save user {}: {}", user.getEmail(), e.getMessage(), e);
            throw new RuntimeException("Failed to persist verification code", e);
        }

        // Send verification email
        try {
            emailService.sendVerificationCodeEmail(user);
            log.info("Verification code sent to {}", user.getEmail());
        } catch (EmailService.EmailSendingException e) {
            log.error("Failed to send verification email to {}: {}", user.getEmail(), e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Generates Uniques password reset link valid for 15 minutes and sends user
     * through mail
     * 
     * @param email the user's email
     * @throws UserNotfoundException throws this exception if user not found with
     *                               provided email
     *
     */
    public void sendPasswordResetLink(String email) {
        UserEntity userEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotfoundException("User not found with email: " + email));
        // generate a string
        if (userEntity.getProvider() != LoginProviders.EMAIL) {
            throw new InvalidLoginTypeException("You can not change password!");
        }
        String passwordResetToken = generateRandomToken(32);
        Instant instant = Instant.now().plus(15, ChronoUnit.MINUTES);
        // generated token and expiry data into user entity object
        userEntity.setPassword_reset_token(passwordResetToken);
        userEntity.setPassword_reset_token_expires_at(Date.from(instant));
        // send verification code
        emailService.sendPasswordResetLink(userEntity);
        userRepository.save(userEntity);
    }

    /**
     * verifies password reset token and if finds valid then changes password
     * 
     * @param token                password reset-token received from user
     * @param resetPasswordRequest request body {@link ResetPasswordRequest}
     * @throws InvalidTokenException    if token is invalid or expired
     * @throws IllegalArgumentException if body is empty
     * @throws RuntimeException         if failed to save in database
     */
    public void changePassword(String token, ResetPasswordRequest resetPasswordRequest) {
        UserEntity user = userRepository.findByValidPasswordResetToken(token, new Date())
                .orElseThrow(() -> new InvalidTokenException("Token is Invalid or expired!"));
        if (resetPasswordRequest.getPassword() == null) {
            throw new IllegalArgumentException("Please provide password to change");
        }
        if (user.getProvider() != LoginProviders.EMAIL) {
            throw new InvalidLoginTypeException(
                    "You can not change password cause you registered with " + user.getProvider());
        }
        user.setPassword(passwordEncoder.encode(resetPasswordRequest.getPassword()));
        user.setPassword_reset_token_expires_at(null);
        user.setPassword_reset_token(null);
        user.setUpdated_at(new Date());
        // remove version from redis
        redisTemplate.delete(VERSION_PREFIX + user.getId());
        sessionRepository.deleteAllByUser(user);
        try {
            userRepository.save(user);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * calls login functions of required oauth provides
     * 
     * @param socialLoginRequestBody {@link SocialLoginRequest} an request object
     *                               received from user
     * @return {@link String} jwt token generated for that user
     */
    public String socialLogin(SocialLoginRequest socialLoginRequestBody, HttpServletRequest request)
            throws JsonProcessingException {
        if (Objects.requireNonNull(socialLoginRequestBody.getProvider()) == LoginProviders.GOOGLE) {
            return googleOauthLogin(socialLoginRequestBody, request);
        } else {
            throw new InvalidLoginTypeException("Current provider is not available");
        }
    }

    /**
     * fetches user profile from Google using access token
     * register user if not exists or returns jwt token if user exists
     * 
     * @param accessToken {@link String} access token for Google apis
     * @throws InvalidLoginTypeException if user tries to log in with different
     *                                   provider than registered
     * @throws IllegalArgumentException  if access token is missing
     * @throws RestClientException       if retrieves invalid response from Google
     * @throws RuntimeException          if failed to save user into database
     */
    private String googleOauthLogin(SocialLoginRequest socialLoginRequest, HttpServletRequest request) {
        if (socialLoginRequest.getAccessToken().isBlank()) {
            log.error("access token is missing");
            throw new IllegalArgumentException("access token is required");
        }
        try {
            String googleProfileApiUrl = "https://www.googleapis.com/oauth2/v2/userinfo";
            // prepare request entity
            HttpHeaders httpHeaders = new HttpHeaders();
            httpHeaders.setBearerAuth(socialLoginRequest.getAccessToken());
            HttpEntity<Void> httpEntity = new HttpEntity<>(httpHeaders);
            log.info("making google user profile request with {}", googleProfileApiUrl);
            // sends request to google for profile details
            ResponseEntity<GoogleUserProfileResponse> googleProfileResponse = restTemplate
                    .exchange(googleProfileApiUrl, HttpMethod.GET, httpEntity, GoogleUserProfileResponse.class);
            // throws error if response is invalid
            if (googleProfileResponse.getStatusCode() != HttpStatus.OK || googleProfileResponse.getBody() == null) {
                log.error("failed to retrieve user profile from google: {}", googleProfileResponse.getStatusCode());
                throw new RestClientException("Invalid response from Google API");
            }
            GoogleUserProfileResponse googleProfile = googleProfileResponse.getBody();
            log.info("successfully user profile retrieved of: {}", googleProfile.getFamily_name());
            // check user exists
            if (googleProfile.getEmail() == null || googleProfile.getEmail().isBlank()) {
                throw new IllegalArgumentException("Email is missing from google response");
            }
            DeviceInfo deviceInfo = socialLoginRequest.getDeviceInfo();
            Optional<UserEntity> optionalUser = userRepository.findByEmail(googleProfile.getEmail());
            if (optionalUser.isPresent()) {
                UserEntity user = optionalUser.get();
                log.info("optional user from database {}", user.getEmail());
                // throws error if provider is different
                if (user.getProvider() != LoginProviders.GOOGLE) {
                    throw new InvalidLoginTypeException("Please login with " + user.getProvider());
                }

                // generate token version
                String tokenVersion = Optional.ofNullable(user.getToken_version())
                        .orElseGet(() -> {
                            String version = Long.toString(ThreadLocalRandom.current().nextLong());
                            user.setToken_version(version);
                            userRepository.save(user);
                            return version;
                        });
                // save user
                LoginSessionEntity loginSession = sessionRepository.findByUserAndDeviceIdAndIsActive(user,
                        deviceInfo.getDeviceId(), true).orElse(
                                LoginSessionEntity.builder()
                                        .browser(deviceInfo.getBrowser())
                                        .deviceId(deviceInfo.getDeviceId())
                                        .deviceType(deviceInfo.getDeviceType())
                                        .isActive(true)
                                        .user(user)
                                        .os(deviceInfo.getOs())
                                        .deviceType(deviceInfo.getDeviceType())
                                        .userAgent(deviceInfo.getUserAgent())
                                        .build());
                loginSession.setLastUsedAt(new Date());
                loginSession.setTokenVersion(tokenVersion);
                loginSession.setIpAddress(getClientIp(request));
                try {
                    sessionRepository.save(loginSession);
                    userRepository.save(user);
                } catch (RuntimeException e) {
                    log.error("failed to save user");
                    throw new RuntimeException(e);
                }
                redisTemplate.opsForHash().put(VERSION_PREFIX + user.getId(), deviceInfo.getDeviceId(), tokenVersion);
                // generate jwt and save user
                return jwtService.getJwtTokenForSession(user, deviceInfo.getDeviceId(), tokenVersion);
            } else {
                String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
                UserEntity user = userRepository.save(UserEntity.builder()
                        .email(googleProfile.getEmail())
                        .provider(LoginProviders.GOOGLE)
                        .is_verified(true)
                        .providerId(googleProfile.getId())
                        .password(googleProfile.getId())
                        .role(UserRoles.USER)
                        .build());
                // save login session
                LoginSessionEntity loginSession = LoginSessionEntity.builder()
                        .browser(deviceInfo.getBrowser())
                        .deviceId(deviceInfo.getDeviceId())
                        .deviceType(deviceInfo.getDeviceType())
                        .isActive(true)
                        .user(user)
                        .os(deviceInfo.getOs())
                        .userAgent(deviceInfo.getUserAgent())
                        .ipAddress(getClientIp(request))
                        .tokenVersion(tokenVersion)
                        .lastUsedAt(new Date())
                        .build();
                sessionRepository.save(loginSession);
                redisTemplate.opsForHash().put(VERSION_PREFIX + user.getId(), deviceInfo.getDeviceId(), tokenVersion);
                return jwtService.getJwtTokenForSession(user, deviceInfo.getDeviceId(), tokenVersion);
            }
        } catch (RestClientException e) {
            log.error("unexpected error encountered during request: {}", e.getMessage());
            throw e;
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Changes user roles
     * 
     * @param changeUserRoleRequest the request body {@link ChangeUserRoleRequest}
     */
    public void changeUserRole(ChangeUserRoleRequest changeUserRoleRequest, HttpServletRequest request) {
        UserEntity operator = getAuthenticatedUser();
        if (operator == null) {
            throw new Unauthorize("Please login!");
        }
        if (operator.getEmail().equals(changeUserRoleRequest.getEmail())) {
            throw new SameUserException("You can not change own role");
        }
        log.info("operator rank is {}", operator.getRole().getRank());
        String deviceId = request.getHeader(DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("Device id is required in header");
        }
        try {
            if (operator.getRole() == null || operator.getRole().equals(UserRoles.USER)
                    || operator.getRole().equals(UserRoles.DOCTOR)) {
                throw new Unauthorize("You don't have permission to perform this action");
            }
            // fetch user
            UserEntity user = userRepository.findByEmail(changeUserRoleRequest.getEmail())
                    .orElseThrow(() -> new UserNotfoundException("User not found with this email"));
            boolean isPermitted = checkUserCanChangeRole(operator.getRole(), user.getRole(),
                    changeUserRoleRequest.getUserRole());
            if (!isPermitted) {
                throw new Unauthorize("you are unauthorized to perform this action");
            }
            user.setRole(changeUserRoleRequest.getUserRole());
            user.setUpdated_at(new Date());
            try {
                userRepository.save(user);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            String USER_VERSION_KEY = VERSION_PREFIX + user.getId();
            try {
                sessionRepository.deleteAllByUser(user);
                redisTemplate.delete(USER_VERSION_KEY);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Process the CSV files from the request and Insert to the database
     * 
     * @param request {@link UploadCsvRequest} object containing CSV file
     * @return {@link Integer} total number of inserted records
     * @throws IllegalArgumentException if file is invalid of empty
     * @throws RuntimeException         if database operation fails
     */
    public int insertUsers(UploadCsvRequest request) {
        MultipartFile file = request.getFile();
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please enter valid file");
        }
        try {
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8));
            CSVFormat csvFormat = CSVFormat.DEFAULT
                    .builder()
                    .setHeader()
                    .setSkipHeaderRecord(true)
                    .setIgnoreHeaderCase(true)
                    .setTrim(true)
                    .build();
            CSVParser csvRecord = csvFormat.parse(reader);
            List<UserEntity> users = csvRecord.stream()
                    .filter(record -> record.get("email") != null || !record.get("email").isEmpty())
                    .map(this::insertUser)
                    .toList();
            try {
                userRepository.saveAll(users);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return users.size();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Transactional
    public String impersonateUser(String email, HttpServletRequest request) throws JsonProcessingException {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Invalid parameters");
        }
        UserEntity performer = this.getAuthenticatedUser();
        if (performer == null) {
            throw new Unauthorize("Please login before perform this action");
        }
        if (performer.getRole() != UserRoles.ADMIN && performer.getRole() != UserRoles.SUPER_ADMIN) {
            throw new Unauthorize("You can not impersonate any user");
        }
        UserEntity targetUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotfoundException("User not found with email:" + email));
        if (targetUser.getRole().getRank() < performer.getRole().getRank()) {
            throw new Unauthorize("You can not impersonate your superior");
        }
        String deviceId = request.getHeader(DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("Device id is required in header");
        }
        String tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        LoginSessionEntity session = sessionRepository.findByUserAndDeviceIdAndIsActive(performer, deviceId, true)
                .orElseThrow(() -> new Unauthorize("No active session found for this device Please login again",
                        HttpStatus.UNAUTHORIZED));
        session.setIsActive(false);
        session.setLastUsedAt(new Date());
        session.setIpAddress(getClientIp(request));
        LoginSessionEntity impersonateSession = LoginSessionEntity
                .builder()
                .browser(session.getBrowser())
                .createdAt(new Date())
                .deviceId(deviceId)
                .deviceType(session.getDeviceType())
                .tokenVersion(tokenVersion)
                .ipAddress(getClientIp(request))
                .os(session.getOs())
                .user(targetUser)
                .userAgent(session.getUserAgent())
                .lastUsedAt(new Date())
                .actualSession(session)
                .impersonatedBy(performer)
                .build();
        sessionRepository.saveAll(List.of(impersonateSession, session));
        String updatedToken = jwtService.getJwtToken(targetUser, performer.getEmail(), tokenVersion, deviceId);
        ListOperations<String, Object> listOps = redisTemplate.opsForList();
        String Key = IMPERSONATE_PREFIX + targetUser.getEmail();
        listOps.rightPush(Key, tokenVersion);
        return updatedToken;
    }

    /**
     * converts valid csv record to UserEntity
     * 
     * @param record {@link CSVRecord} a record containing email and password
     * @return {@link UserEntity} an userEntity
     */
    private UserEntity insertUser(CSVRecord record) {
        String email = record.get("email");
        String password = record.get("password");
        if (email == null || email.isBlank()) {
            return null;
        }
        String decodedPassword = passwordEncoder.encode(password);
        return UserEntity.builder()
                .email(email)
                .password(decodedPassword)
                .is_verified(true)
                .created_at(new Date())
                .isActive(true)
                .provider(LoginProviders.EMAIL)
                .build();
    }

    /**
     * Function end impersonating session retrieved from token and headers
     * 
     * @param request {@link HttpServletRequest} request object
     * @throws InvalidTokenException   if token have invalid version number or
     *                                 missing any data
     * @throws RuntimeException        if any headers are missing
     * @throws UserNotfoundException   if actual user not present in database
     * @throws JsonProcessingException if any failed to create or parse jwt token
     */
    public String exitImpersonating(HttpServletRequest request) throws JsonProcessingException {
        String token = extractAuthorizationToken(request);
        if (!isValidRequestForExitImpersonate(request)) {
            throw new RuntimeException("Not currently impersonating");
        }

        Map<String, Object> claims = jwtService.getJwtClaims(token);
        String versionStr = (String) claims.get("version");
        if (versionStr == null) {
            throw new InvalidTokenException("Invalid or missing version in token");
        }
        long version;
        try {
            version = Long.parseLong(versionStr);
        } catch (NumberFormatException e) {
            throw new InvalidTokenException("Invalid version format in token");
        }
        String userEmail = request.getHeader(USER_EMAIL_HEADER);
        if (userEmail == null || userEmail.isBlank()) {
            throw new RuntimeException("User email header is missing");
        }
        String deviceId = request.getHeader(DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            throw new RuntimeException("Device id is required in header");
        }
        UserEntity impersonatedUser = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UserNotfoundException("User not found with email: " + userEmail));

        String redisKey = IMPERSONATE_PREFIX + userEmail;
        redisTemplate.opsForList().remove(redisKey, 1, String.valueOf(version));
        String actualUserEmail = request.getHeader(IMPERSONATE_BY);
        UserEntity user = userRepository.findByEmail(actualUserEmail)
                .orElseThrow(() -> new UserNotfoundException("user not found with email: " + actualUserEmail));
        String newTokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
        LoginSessionEntity actualSession = sessionRepository.findByUserAndDeviceIdAndIsActive(user, deviceId, false)
                .orElseThrow(() -> new InvalidTokenException("No inactive session found for this device"));
        actualSession.setIsActive(true);
        actualSession.setLastUsedAt(new Date());
        actualSession.setIpAddress(getClientIp(request));
        actualSession.setTokenVersion(newTokenVersion);
        int deactivedSessionCount = sessionRepository.deActiveSessionByUserAndDeviceId(impersonatedUser, deviceId);
        log.info("deactivated {} sessions", deactivedSessionCount);
        sessionRepository.save(actualSession);
        redisTemplate.opsForHash().put(VERSION_PREFIX + user.getId(), deviceId, newTokenVersion);
        return jwtService.getJwtTokenForSession(user, deviceId, newTokenVersion);
    }

    /**
     * Updates the authenticated user's password after validating the old password.
     * 
     * @param changePasswordRequest the request body containing old and new
     *                              passwords
     * @return a new JWT token if the password is successfully updated
     * @throws IllegalArgumentException  if the request body is invalid
     * @throws Unauthorize               if the user is not authenticated or the old
     *                                   password is incorrect
     * @throws InvalidLoginTypeException if the user registered with a different
     *                                   provider
     * @throws RuntimeException          if saving the updated user fails
     */
    public String updatePassword(ChangePasswordRequest changePasswordRequest, HttpServletRequest request) {
        if (changePasswordRequest.getNewPassword().isEmpty() || changePasswordRequest.getOldPassword().isEmpty()) {
            throw new IllegalArgumentException("Invalid argumets");
        }
        String deviceId = request.getHeader(DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("Device id is required in header");
        }
        UserEntity user = getAuthenticatedUser();
        if (user == null) {
            throw new Unauthorize("Please login!");
        }
        if (user.getProvider() != LoginProviders.EMAIL) {
            throw new InvalidLoginTypeException(
                    "You can not change password cause you registered with " + user.getProvider());
        }

        if (!passwordEncoder.matches(changePasswordRequest.getOldPassword(), user.getPassword())) {
            throw new Unauthorize("Old password is incorrect");
        }
        if (passwordEncoder.matches(changePasswordRequest.getNewPassword(), user.getPassword())) {
            throw new IllegalArgumentException("New password must be different from old password");
        }

        user.setPassword(passwordEncoder.encode(changePasswordRequest.getNewPassword()));
        user.setUpdated_at(new Date());
        LoginSessionEntity session = sessionRepository.findByUserAndDeviceIdAndIsActive(user, deviceId, true)
                .orElseThrow(() -> new Unauthorize("No active session found for this device Please login again",
                        HttpStatus.UNAUTHORIZED));
        String tokenVersion;
        if (changePasswordRequest.isLogoutFromOtherDevices()) {
            tokenVersion = String.valueOf(ThreadLocalRandom.current().nextLong());
            LoginSessionEntity newSession = LoginSessionEntity.builder()
                    .browser(session.getBrowser())
                    .createdAt(new Date())
                    .deviceId(deviceId)
                    .deviceType(session.getDeviceType())
                    .tokenVersion(tokenVersion)
                    .ipAddress(getClientIp(request))
                    .os(session.getOs())
                    .user(user)
                    .userAgent(session.getUserAgent())
                    .lastUsedAt(new Date())
                    .build();
            sessionRepository.deleteAllByUser(user);
            sessionRepository.save(newSession);
            redisTemplate.delete(VERSION_PREFIX + user.getId());
            redisTemplate.opsForHash().put(VERSION_PREFIX + user.getId(), deviceId, tokenVersion);
        } else {
            tokenVersion = session.getTokenVersion();
            session.setLastUsedAt(new Date());
            session.setIpAddress(getClientIp(request));
            sessionRepository.save(session);
        }
        try {
            userRepository.save(user);
            return jwtService.getJwtTokenForSession(user, deviceId, tokenVersion);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Deletes a user by email. Supports both hard and soft delete based on the
     * hardDelete flag.
     *
     * @param email      The email of the user to be deleted.
     * @param hardDelete If true, performs a hard delete; if false, performs a soft
     *                   delete.
     * @throws IllegalArgumentException if the email is null or empty.
     * @throws Unauthorize              if the authenticated user does not have
     *                                  permission to delete the target user.
     * @throws UserNotfoundException    if no user is found with the provided email.
     * @throws RuntimeException         if any database operation fails.
     */
    public void deleteUserByEmail(String email, boolean hardDelete) {
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Invalid parameters");
        }
        UserEntity performer = this.getAuthenticatedUser();
        if (performer == null) {
            throw new Unauthorize("Please login before perform this action");
        }
        if (performer.getRole() != UserRoles.ADMIN && performer.getRole() != UserRoles.SUPER_ADMIN
                && !performer.getEmail().equals(email)) {
            throw new Unauthorize("You can not delete any user");
        }
        if (performer.getRole().getRank() > 1 && hardDelete) {
            throw new Unauthorize("You don't have permission to perform hard delete");
        }
        UserEntity targetUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotfoundException("User not found with email:" + email));
        if (targetUser.getRole().getRank() < performer.getRole().getRank()) {
            throw new Unauthorize("You can not delete your superior");
        }
        try {
            if (hardDelete) {
                userRepository.delete(targetUser);
            } else {
                targetUser.setIsActive(false);
                targetUser.setDeleted_at(new Date());
                targetUser.setUpdated_at(new Date());
                userRepository.save(targetUser);
            }
            String USER_VERSION_KEY = VERSION_PREFIX + targetUser.getId();
            sessionRepository.deleteAllByUser(targetUser);
            redisTemplate.delete(USER_VERSION_KEY);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Logs out the authenticated user from the current device or all devices based
     * on the allDevices flag.
     *
     * @param request    The HTTP request object containing headers.
     * @param allDevices If true, logs out from all devices; if false, logs out
     *                   from the current device only.
     * @throws Unauthorize              if the user is not authenticated.
     * @throws IllegalArgumentException if the device ID header is missing or
     *                                  invalid.
     * @throws RuntimeException         if any database or Redis operation fails.
     */
    public void logoutUser(HttpServletRequest request, boolean allDevices) {
        UserEntity user = getAuthenticatedUser();
        if (user == null) {
            throw new Unauthorize("Please login!");
        }
        String deviceId = request.getHeader(DEVICE_ID_HEADER);
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("Device id is required in header");
        }

        if (allDevices) {
            int deactivatedSession = sessionRepository.deActiveSessionByUser(user);
            log.info("deactivated {} sessions", deactivatedSession);
            try {
                redisTemplate.delete(VERSION_PREFIX + user.getId());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            return;
        }
        try {
            redisTemplate.opsForHash().delete(VERSION_PREFIX + user.getId(), deviceId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        int deactivedSessionCount = sessionRepository.deActiveSessionByUserAndDeviceId(user, deviceId);
        log.info("deactivated {} sessions", deactivedSessionCount);

    }

    // var users = authService.getAllUsers(role, search, page, size, sort_by,
    // sort_dir, is_active);
    public PaginationResponse<UsersResponse> getAllUsers(UserRoles role, String search, int page, int size,
            List<String> sort_by,
            String sort_dir, Boolean is_active, Boolean is_verified, LoginProviders provider) {
        if (page < 0 || size <= 0) {
            throw new IllegalArgumentException("Invalid page or size parameters");
        }
        if (search == null) {
            search = "";
        }
        Sort sort = Sort.unsorted();
        List<Sort.Order> orders = new ArrayList<>();
        if (sort_by != null && !sort_by.isEmpty()) {
            for (String sortField : sort_by) {
                if ("desc".equalsIgnoreCase(sort_dir)) {
                    orders.add(Sort.Order.desc(sortField));
                } else {
                    orders.add(Sort.Order.asc(sortField));
                }
            }
            sort = Sort.by(orders);
        }
        log.info("page {} and limit {}", page, size);
        Pageable pageable = PageRequest.of(page, size, sort);
        Page<UsersResponse> userPage = userRepository.findByFilters(search, role, is_active, is_verified, provider,
                pageable);
        log.info("Retrieved {} users", userPage.getNumberOfElements());
        PaginationResponse<UsersResponse> response = PaginationResponse.<UsersResponse>builder()
                .currentPageSize(userPage.getNumberOfElements())
                .totalItems(userPage.getTotalElements())
                .totalPages(userPage.getTotalPages())
                .pageSize(size)
                .data(userPage.getContent())
                .build();
        return response;
    }

    /**
     * Validates if the request is eligible for exiting impersonation.
     *
     * @param request The HTTP request object.
     * @return True if the request is valid for exiting impersonation, false
     *         otherwise.
     */
    private boolean isValidRequestForExitImpersonate(HttpServletRequest request) {
        String email = request.getHeader(IMPERSONATE_BY);
        String impersonatingHeader = request.getHeader(IMPERSONATE);
        return email != null && !email.isEmpty() &&
                "true".equalsIgnoreCase(impersonatingHeader);
    }

    /**
     * Extracts the JWT token from the Authorization header.
     *
     * @param request The HTTP request object.
     * @return The extracted JWT token.
     * @throws Unauthorize If the Authorization header is missing or invalid.
     */
    private String extractAuthorizationToken(HttpServletRequest request) {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String BEARER_PREFIX = "Bearer ";
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new Unauthorize("Invalid or missing Authorization header");
        }
        return authHeader.substring(BEARER_PREFIX.length());
    }

    public String getClientIp(HttpServletRequest request) {
        String header = request.getHeader("X-Forwarded-For");
        if (header == null || header.isEmpty()) {
            return request.getRemoteAddr();
        }
        // First IP in list is the original client
        return header.split(",")[0].trim();
    }

    /**
     * Check role hierarchy that is performer is superior to target role and current
     * user role
     * 
     * @param performerRole   - {@link UserRoles} role of Action performer
     * @param currentUserRole - {@link UserRoles} current role user
     * @param targetRole      - {@link UserRoles} target role
     * @return true if performer is superior else false
     * @throws IllegalArgumentException if any function parameters are invalid
     */
    public boolean checkUserCanChangeRole(UserRoles performerRole, UserRoles currentUserRole, UserRoles targetRole) {
        if (performerRole == null || currentUserRole == null || targetRole == null) {
            throw new IllegalArgumentException("Invalid parameter to perform this action");
        }
        int indexOfPerformerRole = performerRole.getRank();
        int indexOfUserRole = currentUserRole.getRank();
        int indexOfRoleToChange = targetRole.getRank();
        if (indexOfPerformerRole < 0 || indexOfUserRole < 0 || indexOfRoleToChange < 0) {
            throw new IllegalArgumentException("Invalid roles!");
        }
        return indexOfPerformerRole <= indexOfUserRole && indexOfPerformerRole <= indexOfRoleToChange;
    }

    /**
     * Generates a random token as a Base64-encoded string.
     *
     * @param length the number of random bytes to generate (must be positive)
     * @return a Base64-URL-encoded string representing the random bytes
     * @throws IllegalArgumentException if length is less than 1
     */
    public static String generateRandomToken(int length) {
        if (length < 1) {
            throw new IllegalArgumentException("Token length must be at least 1");
        }
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateOtp(int size) {
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    /**
     * A custom exception to user if already verified and sends verification code
     * request
     */
    public static class AlreadyVerifiedException extends RuntimeException {
        public AlreadyVerifiedException(String message) {
            super(message);
        }
    }

    /**
     * A custom exception if User not found with provided details
     */
    public static class UserNotfoundException extends RuntimeException {
        public UserNotfoundException(String message) {
            super(message);
        }
    }

    /**
     * A custom exception if password reset token is invalid
     */
    public static class InvalidTokenException extends RuntimeException {
        public InvalidTokenException(String message) {
            super(message);
        }
    }

    /**
     * A custom exception if user try to log in with different provider than
     * registered
     */
    public static class InvalidLoginTypeException extends RuntimeException {
        public InvalidLoginTypeException(String message) {
            super(message);
        }
    }

    public static class SameUserException extends RuntimeException {
        public SameUserException(String message) {
            super(message);
        }
    }
}

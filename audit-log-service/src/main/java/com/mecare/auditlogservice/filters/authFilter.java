package com.mecare.auditlogservice.filters;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mecare.auditlogservice.utils.UserEntity;
import com.mecare.auditlogservice.utils.UserPrincipal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class authFilter extends OncePerRequestFilter {
    private static final String ID_HEADER_KEY = "x-user-id";
    private static final String EMAIL_HEADER_KEY = "x-user-email";
    private static final String ROLE_HEADER_KEY = "x-user-role";
    private static final String VERIFIED_HEADER_KEY = "x-user-verified";
    private static final String IMPERSONATE_BY = "x-user-impersonate_by";
    private static final String IMPERSONATE = "x-user-impersonate";
    private static final String DEVICE_ID_HEADER_KEY = "x-device-id";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Avoid overwriting existing authentication
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            UserEntity user = buildUserFromRequest(request);
            UserPrincipal principal = new UserPrincipal(user);

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    principal.getAuthorities());

            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (IllegalArgumentException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator")
                || path.startsWith("/health")
                || path.startsWith("/internal");
    }

    UserEntity buildUserFromRequest(HttpServletRequest request) {
        String id = request.getHeader(ID_HEADER_KEY);
        String email = request.getHeader(EMAIL_HEADER_KEY);
        String role = request.getHeader(ROLE_HEADER_KEY);
        boolean verified = Boolean.TRUE.equals(request.getHeader(VERIFIED_HEADER_KEY));
        boolean impersonate = Boolean.TRUE.equals(request.getHeader(IMPERSONATE));
        String impersonateBy = request.getHeader(IMPERSONATE_BY);
        String deviceId = request.getHeader(DEVICE_ID_HEADER_KEY);
        // validations
        if (id == null || email == null || role == null || deviceId == null) {
            throw new RuntimeException("Invalid user details");
        }
        return UserEntity.builder()
                .id(id)
                .email(email)
                .role(role)
                .verified(verified)
                .isImpersonate(impersonate)
                .impersonateBy(impersonateBy)
                .deviceId(deviceId)
                .build();
    }
}

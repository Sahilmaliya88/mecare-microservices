package com.example.authservice.filter;

import com.example.authservice.services.EmailService;
import com.example.authservice.utils.CustomAuthenticationService;
import com.example.authservice.utils.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Component
public class AuthFilter extends OncePerRequestFilter {
    private static final String EMAIL_HEADER_KEY= "x-user-email";
    private static final String ROLE_HEADER_KEY = "x-user-role";
    private static final String VERIFIED_HEADER_KEY = "x-user-verified";

    @Autowired
    private CustomAuthenticationService customAuthenticationService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        String userEmail = request.getHeader(EMAIL_HEADER_KEY);
        String userRole = request.getHeader(ROLE_HEADER_KEY);
        String isUserVerified = request.getHeader(VERIFIED_HEADER_KEY);
        if (!isValidHeader(userEmail, userRole, isUserVerified)) {
            filterChain.doFilter(request, response);
            return;
        }
        //set principal to security context if email present
        UserPrincipal userPrincipal = (UserPrincipal) customAuthenticationService.loadUserByUsername(userEmail);
        if (userPrincipal == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("{\"error\": \"User not found\"}");
            return;
        }
        // Create authentication token
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userPrincipal,
                null, // Credentials not needed for header-based auth
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + userRole))
        );
        authenticationToken.setDetails(new WebAuthenticationDetails(request));

        // Set authentication in SecurityContext
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        filterChain.doFilter(request,response);
    }
    /**
     * Validates the presence and non-emptiness of required headers.
     *
     * @param email        The email header value
     * @param role         The role header value
     * @param isVerified   The verified header value
     * @return true if all headers are valid, false otherwise
     */
    private boolean isValidHeader(String email, String role, String isVerified) {
        return email != null && !email.trim().isEmpty() &&
                role != null && !role.trim().isEmpty() &&
                isVerified != null && !isVerified.trim().isEmpty();
    }
}

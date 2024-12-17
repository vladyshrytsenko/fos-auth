package com.example.config;

import com.example.service.UserService;
import com.example.service.auth.GoogleOAuthService;
import com.example.service.auth.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final GoogleOAuthService googleOAuthService;
    private final UserService userService;


    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring("Bearer ".length());

        if (this.jwtService.isJwtToken(token)) {
            this.handleJwtToken(request, response, filterChain, token);
        } else if (this.googleOAuthService.isGoogleOAuthToken(token)) {
            this.handleGoogleToken(token, request);
        }

        System.out.println("Before filter chain, authentication: " + SecurityContextHolder.getContext().getAuthentication());
        filterChain.doFilter(request, response);
        System.out.println("After filter chain, authentication: " + SecurityContextHolder.getContext().getAuthentication());
    }

    private void handleJwtToken(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain,
        String token) throws IOException, ServletException {

        final String userEmail;
        userEmail = this.jwtService.extractUsername(token);

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            if (this.jwtService.isTokenValid(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
                );

                authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
                );

                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
    }

    private void handleGoogleToken(String token, HttpServletRequest request) {
        String googleUserId = this.googleOAuthService.validateTokenAndGetUserId(token);

        if (googleUserId == null) {
            System.out.println("Google token validation failed for token: " + token);
        }

        if (googleUserId != null) {
            UserDetails userDetails = this.userService.loadUserByGoogleId(googleUserId);

            if (userDetails == null) {
                System.out.println("No user found for Google ID: " + googleUserId);
            }

            UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }
}

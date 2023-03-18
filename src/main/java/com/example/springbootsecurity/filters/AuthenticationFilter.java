package com.example.springbootsecurity.filters;

import com.example.springbootsecurity.services.AuthenticationService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Slf4j
public class AuthenticationFilter extends OncePerRequestFilter {

    private final AuthenticationService authenticationService;

    private final UserDetailsService userDetailsService;
    private static final String HEADER = "Authorization";

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain) throws ServletException, IOException {

        // Log the incoming request and response objects
        log.debug("Request - {}", request);
        log.debug("Response - {}", response);

        final String authHeader = request.getHeader(HEADER);

        // Log the auth header value
        log.debug("Authorization header - {}", authHeader);

        final String jwtToken;
        final String username;

        // If the auth header is null or doesn't start with "Bearer ", pass the request on to the next filter in the chain
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No JWT token found in authorization header. Passing request down the filter chain.");
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the JWT token from the auth header
        jwtToken = authHeader.substring(7);
        log.debug("Extracted JWT token - {}", jwtToken);

        // Extract the username from the JWT token
        username = authenticationService.extractUsername(jwtToken);
        log.debug("Extracted username from JWT token - {}", username);

        // If we were able to extract a username from the JWT token, and no authentication is currently set in the SecurityContextHolder...
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Load the UserDetails object for the given username
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // If the JWT token is valid for the given user...
            if (authenticationService.isTokenValid(jwtToken, userDetails)) {
                log.debug("JWT token is valid for user - {}", username);

                // Create a new UsernamePasswordAuthenticationToken for the user
                UsernamePasswordAuthenticationToken usernamePasswordAuthToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // Set the authentication details for the token
                usernamePasswordAuthToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Set the authentication token in the SecurityContextHolder
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthToken);
                log.debug("Set authentication token in SecurityContextHolder - {}", usernamePasswordAuthToken);
            } else {
                log.debug("JWT token is not valid for user - {}", username);
            }
        } else {
            log.debug("No username extracted from JWT token - {}", jwtToken);
        }

        filterChain.doFilter(request, response);
    }
}

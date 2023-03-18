package com.example.springbootsecurity.services;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

public interface AuthenticationService {
    String getToken(UserDetails userDetails);

    String generateToken(Map<String, Object> extraClaims, UserDetails userDetails);

    boolean isTokenValid(String token, UserDetails userDetails);

    String extractUsername(String jwtToken);

    <T> T extractClaim(String jwtToken, Function<Claims, T> claimsResolver);
}

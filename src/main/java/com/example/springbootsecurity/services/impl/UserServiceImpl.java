package com.example.springbootsecurity.services.impl;

import com.example.springbootsecurity.enums.Role;
import com.example.springbootsecurity.modals.User;
import com.example.springbootsecurity.modals.requests.AuthRequest;
import com.example.springbootsecurity.modals.requests.RegisterRequest;
import com.example.springbootsecurity.modals.responses.AuthResponse;
import com.example.springbootsecurity.modals.responses.RegisterResponse;
import com.example.springbootsecurity.repositories.UserRepository;
import com.example.springbootsecurity.services.AuthenticationService;
import com.example.springbootsecurity.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationService authenticationService;
    private final AuthenticationManager authenticationManager;

    @Override
    public RegisterResponse registerUser(RegisterRequest registerRequest) {
        User user = UserDTOtoMODAL(registerRequest);
        userRepository.save(user);
        return UserMODALtoDTO(user);
    }

    private RegisterResponse UserMODALtoDTO(User user) {
        return RegisterResponse.builder()
                .id(user.getId())
                .fullname(user.getFirstname() + " " + user.getLastname())
                .username(user.getUsername())
                .email(user.getEmail())
                .createdOn(user.getCreatedOn())
                .role(user.getRole())
                .build();
    }

    private User UserDTOtoMODAL(RegisterRequest registerRequest) {
        return User.builder()
                .id(UUID.randomUUID())
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .createdOn(LocalDateTime.now())
                .updatedOn(LocalDateTime.now())
                .role(registerRequest.getRole() != null ? Role.valueOf(registerRequest.getRole().toUpperCase()) : Role.USER)
                .build();
    }

    @Override
    public AuthResponse authenticateUser(AuthRequest request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
        var user = userRepository.findByUsername(request.getUsername())
                .orElseThrow();

        String token = authenticationService.getToken(user);
        return AuthResponse.builder()
                .token(token)
                .build();
    }
}

package com.example.springbootsecurity.services;

import com.example.springbootsecurity.modals.requests.AuthRequest;
import com.example.springbootsecurity.modals.requests.RegisterRequest;
import com.example.springbootsecurity.modals.responses.AuthResponse;
import com.example.springbootsecurity.modals.responses.RegisterResponse;

public interface UserService {
    RegisterResponse registerUser(RegisterRequest registerRequest);

    AuthResponse authenticateUser(AuthRequest request);
}

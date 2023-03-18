package com.example.springbootsecurity.modals.responses;

import com.example.springbootsecurity.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterResponse {
    private UUID id;
    private String fullname;
    private String username;
    private String email;
    private LocalDateTime createdOn;
    private Role role;
}

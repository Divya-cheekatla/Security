package com.security_service.Security.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    private String token;
    private String userName;
    private List<String> roles;
}
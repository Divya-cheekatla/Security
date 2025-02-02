package com.security_service.Security.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class TokenValidationResponse {
    private String message;

    public TokenValidationResponse() {
    }

    public TokenValidationResponse(String message) {
        this.message = message;
    }

}

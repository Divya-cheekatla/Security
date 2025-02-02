package com.security_service.Security.exceptions;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MissingRequestHeaderException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ResponseEntity<String> handleMissingRequestHeaderException(MissingRequestHeaderException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("Missing required header: " + ex.getHeaderName());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGeneralException(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Exception Occurred: " + ex.getMessage());
    }

    @ExceptionHandler({ExpiredJwtException.class, MalformedJwtException.class, SignatureException.class, IllegalArgumentException.class})
    public ResponseEntity<String> handleJWTException(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body("JWT token exception: " + ex.getMessage());
    }
}
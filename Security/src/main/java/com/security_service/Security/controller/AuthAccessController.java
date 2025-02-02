package com.security_service.Security.controller;

import com.security_service.Security.jwt.JWTUtils;
import com.security_service.Security.model.AuthenticationRequest;
import com.security_service.Security.model.AuthenticationResponse;
import com.security_service.Security.model.TokenValidationResponse;
import com.security_service.Security.validate.TokenValidate;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthAccessController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTUtils jwtTokenUtil;
    @Autowired
    private TokenValidate tokenValidate;

    @GetMapping("/admin-access")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Hi Admin";
    }

    @GetMapping("/user-access")
    @PreAuthorize("hasRole('USER')")
    public String userAccess() {
        return "Hi User";
    }

    @RequestMapping(value = "/generateToken", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@NonNull @RequestBody AuthenticationRequest authenticationRequest)
            throws Exception {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
        SecurityContextHolder.getContext().setAuthentication(authentication);
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        final String token = jwtTokenUtil.generateToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toUnmodifiableList());
        AuthenticationResponse response = new AuthenticationResponse(token, userDetails.getUsername(), roles);

        return ResponseEntity.ok(response);
    }

    @GetMapping({"/validateToken"})
    public Boolean validateToken(@RequestHeader(name = "Authorization") String authorizationToken, @RequestHeader(name = "roles") List<String> roles) {
        log.info("validateToken start");
        if (tokenValidate.validateToken(authorizationToken, roles)) {
            return ResponseEntity.ok(new TokenValidationResponse("Valid token")).hasBody();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenValidationResponse("Invalid token")).hasBody();
        }
    }
}

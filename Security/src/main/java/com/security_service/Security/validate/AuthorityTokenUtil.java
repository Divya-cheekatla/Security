package com.security_service.Security.validate;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class AuthorityTokenUtil {

    @Value("${security.jwt.secret-key}")
    private String jwtSecret;

    public List<String> checkPermission(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            log.info("Claims{}", claims);
            return claims.get("roles", List.class);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

}

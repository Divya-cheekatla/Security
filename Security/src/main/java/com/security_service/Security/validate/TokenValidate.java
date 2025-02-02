package com.security_service.Security.validate;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
public class TokenValidate {

    @Value("${security.jwt.secret-key}")
    private String SECRET_KEY;
    @Autowired
    AuthorityTokenUtil authorityTokenUtil;

    public boolean validateToken(String token, List<String> roles) {
        if (SECRET_KEY == null || SECRET_KEY.isEmpty())
            throw new IllegalArgumentException("Not found secret key in structure");

        if (token.startsWith("Bearer "))
            token = token.replace("Bearer ", "");

        try {
            Claims claims = Jwts
                    .parser()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            long currentTimeMillis = System.currentTimeMillis();
            boolean expiredFlag = claims.getExpiration().getTime() >= currentTimeMillis;
            if (!expiredFlag) {
                throw new IllegalArgumentException("Token has expired.");
            } else {
                List<String> authorities = authorityTokenUtil.checkPermission(token);
                if (authorities == null || authorities.stream().noneMatch(roles::contains)) {
                    throw new IllegalArgumentException("Authentication failed due to role");
                }
                return true;
            }

        } catch (ExpiredJwtException ex) {
            log.info("error");
            throw new IllegalArgumentException("Token has expired.");
        } catch (MalformedJwtException ex) {
            throw new IllegalArgumentException("Invalid token.");
        } catch (SignatureException ex) {
            throw new IllegalArgumentException("Token validation error.");
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Token validation error: " + ex.getMessage());
        }
    }

}

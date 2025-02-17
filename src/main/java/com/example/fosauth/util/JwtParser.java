package com.example.fosauth.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtParser {

    @PostConstruct
    public void init() {
        if (secretKeyBase64 != null && !secretKeyBase64.isEmpty()) {
            SECRET_KEY = Keys.hmacShaKeyFor(secretKeyBase64.getBytes(StandardCharsets.UTF_8));
        } else {
            throw new IllegalArgumentException("Secret key must not be null or empty");
        }
    }

    public static Claims extractAllClaims(String token) {
        if (token.startsWith("Bearer ")) {
            token = token.replace("Bearer ", "");
        }
        return Jwts.parser()
            .setSigningKey(SECRET_KEY)
            .parseClaimsJws(token)
            .getBody();
    }

    @Value("${jwt.secret-key}")
    private String secretKeyBase64;

    public static SecretKey SECRET_KEY;
}

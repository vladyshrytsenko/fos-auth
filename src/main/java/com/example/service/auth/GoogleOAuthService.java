package com.example.service.auth;

import com.example.model.GoogleUserInfo;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

@Service
public class GoogleOAuthService {

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    public boolean isGoogleOAuthToken(String token) {
        return token != null && token.length() > 100;
    }

    public String validateTokenAndGetUserId(String token) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                .build();

            GoogleIdToken idToken = verifier.verify(token);
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();
                return payload.getSubject();
            } else {
                throw new IllegalArgumentException("Invalid Google ID Token");
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Token verification failed", e);
        }
    }

    public GoogleUserInfo validateTokenAndGetUserInfo(String token) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(Collections.singletonList(googleClientId))
                .build();

            GoogleIdToken idToken = verifier.verify(token);
            if (idToken != null) {
                GoogleIdToken.Payload payload = idToken.getPayload();

                String googleUserId = payload.getSubject();
                String email = payload.getEmail();
                String name = (String) payload.get("name");

                return new GoogleUserInfo(googleUserId, email, name);
            } else {
                throw new IllegalArgumentException("Invalid Google ID Token");
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Token verification failed", e);
        }
    }
}


package com.example.fosauth.service.auth;

import com.example.fosauth.exception.EntityNotFoundException;
import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.model.response.AuthenticationResponse;
import com.example.fosauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(UserDto userRequestDTO) {
        User userToSave = User.builder()
            .username(userRequestDTO.getUsername())
            .password(passwordEncoder.encode(userRequestDTO.getPassword()))
            .email(userRequestDTO.getEmail())
            .role(Role.USER)
            .build();

        User createdUser = this.userRepository.save(userToSave);
        return getAuthenticationResponse(createdUser);
    }

    public AuthenticationResponse authenticate(UserDto user) {
        this.authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword())
        );

        User userByEmail = this.userRepository.findByEmail(user.getEmail())
            .orElseThrow(() -> new EntityNotFoundException(User.class));
        return getAuthenticationResponse(userByEmail);
    }

    private AuthenticationResponse getAuthenticationResponse(User saved) {
        String generatedToken = this.jwtService.generateToken(saved);

        return AuthenticationResponse.builder()
            .token(generatedToken)
            .build();
    }
}


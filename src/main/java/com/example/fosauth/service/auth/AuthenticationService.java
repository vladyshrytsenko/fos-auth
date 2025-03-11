package com.example.fosauth.service.auth;

import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.model.response.AuthenticationResponse;
import com.example.fosauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.apache.commons.lang3.StringUtils.*;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthenticationResponse register(UserDto userRequestDTO) {
        User userToSave = User.builder()
            .username(userRequestDTO.getUsername())
            .password(passwordEncoder.encode(userRequestDTO.getPassword()))
            .email(userRequestDTO.getEmail())
            .role(isNotBlank(userRequestDTO.getRole()) ?
                Role.valueOf(userRequestDTO.getRole()) : Role.USER
            )
            .build();

        User createdUser = this.userRepository.save(userToSave);
        return new AuthenticationResponse(
            createdUser.getUsername(),
            createdUser.getEmail(),
            createdUser.getRole()
        );
    }
}

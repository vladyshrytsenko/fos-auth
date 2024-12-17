package com.example.service;

import com.example.exception.EntityNotFoundException;
import com.example.model.GoogleUserInfo;
import com.example.model.dto.UserDto;
import com.example.model.entity.User;
import com.example.model.enums.Role;
import com.example.repository.UserRepository;
import com.example.service.auth.GoogleOAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final GoogleOAuthService googleOAuthService;

    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            return UserDto.toDto(user);
        }
        throw new RuntimeException("User not authenticated");
    }

    public UserDto findByGoogleId(String googleId) {
        Optional<User> userByGoogleIdOptional = userRepository.findByGoogleUserId(googleId);
        return userByGoogleIdOptional.map(UserDto::toDto).orElse(null);
    }

    public UserDto getById(Long id) {
        User userById = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userById);
    }

    public UserDto createUserFromGoogle(String googleUserId, String token) {
        User newUser = new User();
        newUser.setGoogleUserId(googleUserId);

        GoogleUserInfo googleUserInfo = this.googleOAuthService.validateTokenAndGetUserInfo(token);
        newUser.setRole(Role.USER);
        newUser.setUsername(googleUserInfo.getName());
        newUser.setEmail(googleUserInfo.getEmail());
        User createdUser = userRepository.save(newUser);

        return UserDto.toDto(createdUser);
    }

    public List<UserDto> findAll() {
        List<User> userList = userRepository.findAll();
        return UserDto.toDtoList(userList);
    }

    public UserDto findByRole(Role role) {
        User userByRole = userRepository.findByRole(role).orElse(null);
        return userByRole != null ? UserDto.toDto(userByRole) : null;
    }

    public UserDto getByUsername(String username) {
        User userByUsername = userRepository.findByUsername(username)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userByUsername);
    }

    public UserDto getByEmail(String email) {
        User userEmail = userRepository.findByEmail(email)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userEmail);
    }

    public UserDetails loadUserByGoogleId(String googleUserId) throws UsernameNotFoundException {
        return userRepository.findByGoogleUserId(googleUserId)
            .map(user -> new org.springframework.security.core.userdetails.User(
                user.getUsername(), user.getPassword(), user.getAuthorities()))
            .orElseThrow(() -> new UsernameNotFoundException("User not found with Google ID: " + googleUserId));
    }

    public UserDto update(Long id, UserDto userRequest) {
        User userById = userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        userById.setUsername(userRequest.getUsername());
        userById.setEmail(userRequest.getEmail());
        userById.setRole(Role.valueOf(userRequest.getRole()));

        User updatedUser = userRepository.save(userById);
        return UserDto.toDto(updatedUser);
    }

    public void delete(Long id) {
        userRepository.deleteById(id);
    }
}


package com.example.fosauth.service;

import com.example.fosauth.exception.EntityNotFoundException;
import com.example.fosauth.model.GoogleUserInfo;
import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.repository.UserRepository;
import com.example.fosauth.service.auth.GoogleOAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    public UserDto findByGoogleId(String googleId) {
        Optional<User> userByGoogleIdOptional = this.userRepository.findByGoogleUserId(googleId);
        return userByGoogleIdOptional.map(UserDto::toDto).orElse(null);
    }

    public UserDto getById(Long id) {
        User userById = this.userRepository.findById(id)
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
        User createdUser = this.userRepository.save(newUser);

        return UserDto.toDto(createdUser);
    }

    public List<UserDto> findAll() {
        List<User> userList = this.userRepository.findAll();
        return UserDto.toDtoList(userList);
    }

    public List<User> findAllEntities() {
        return this.userRepository.findAll();
    }

    public UserDto findByRole(Role role) {
        User userByRole = this.userRepository.findByRole(role).orElse(null);
        return userByRole != null ? UserDto.toDto(userByRole) : null;
    }

    public UserDto getByUsername(String username) {
        User userByUsername = this.userRepository.findByUsername(username)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userByUsername);
    }

    public UserDto getByEmail(String email) {
        User userEmail = this.userRepository.findByEmail(email)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userEmail);
    }

    public UserDetails loadUserByGoogleId(String googleUserId) throws UsernameNotFoundException {
        return this.userRepository.findByGoogleUserId(googleUserId)
            .map(user -> new org.springframework.security.core.userdetails.User(
                user.getUsername(), user.getPassword(), user.getAuthorities()))
            .orElseThrow(() -> new UsernameNotFoundException("User not found with Google ID: " + googleUserId));
    }

    public UserDto update(Long id, UserDto userRequest) {
        User userById = this.userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        userById.setUsername(userRequest.getUsername());
        userById.setEmail(userRequest.getEmail());
        userById.setRole(Role.valueOf(userRequest.getRole()));

        User updatedUser = this.userRepository.save(userById);
        return UserDto.toDto(updatedUser);
    }

    public void delete(Long id) {
        this.userRepository.deleteById(id);
    }

    private final UserRepository userRepository;
    private final GoogleOAuthService googleOAuthService;
}

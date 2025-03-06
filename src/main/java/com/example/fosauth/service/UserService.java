package com.example.fosauth.service;

import com.example.fosauth.exception.EntityNotFoundException;
import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    public UserDto getById(Long id) {
        User userById = this.userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        return UserDto.toDto(userById);
    }

    public List<UserDto> findAll() {
        List<User> users = this.userRepository.findAll();
        return UserDto.toDtoList(users);
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
}

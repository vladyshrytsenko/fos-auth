package com.example.fosauth.service;

import com.example.fosauth.exception.EntityNotFoundException;
import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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

    public Page<User> findAll(Pageable pageable) {
        return this.userRepository.findAll(pageable);
    }

    public List<User> findAllEntities() {
        return this.userRepository.findAll();
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

    public UserDto updateById(Long id, UserDto userRequest) {
        User userById = this.userRepository.findById(id)
            .orElseThrow(() -> new EntityNotFoundException(User.class));

        userById.setUsername(userRequest.getUsername());
        userById.setEmail(userRequest.getEmail());
        userById.setRole(Role.valueOf(userRequest.getRole()));

        User updatedUser = this.userRepository.save(userById);
        return UserDto.toDto(updatedUser);
    }

    public void deleteById(Long id) {
        this.userRepository.deleteById(id);
    }

    private final UserRepository userRepository;
}

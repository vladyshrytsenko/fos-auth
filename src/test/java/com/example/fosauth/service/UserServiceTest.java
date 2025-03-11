package com.example.fosauth.service;

import com.example.fosauth.MockData;
import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import com.example.fosauth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class UserServiceTest {

    @Test
    void getById() {
        User user = MockData.user();
        when(this.userRepository.findById(1L)).thenReturn(Optional.of(user));

        UserDto result = this.userService.getById(1L);
        assertNotNull(result);
        assertEquals("test@mail.com", result.getEmail());
        verify(this.userRepository, times(1)).findById(1L);
    }

    @Test
    void findAll() {
        List<User> userList = MockData.userList();
        when(this.userRepository.findAll()).thenReturn(userList);

        List<UserDto> result = this.userService.findAll();
        assertNotNull(result);
        assertEquals(2, result.size());
        verify(this.userRepository, times(1)).findAll();
    }

    @Test
    void findByRole() {
        User user = MockData.user();
        when(this.userRepository.findByRole(any(Role.class))).thenReturn(Optional.of(user));

        UserDto result = this.userService.findByRole(Role.USER);
        assertNotNull(result);
        assertEquals("USER", result.getRole());
        verify(this.userRepository, times(1)).findByRole(Role.USER);
    }

    @Test
    void getByUsername() {
        User user = MockData.user();
        when(this.userRepository.findByUsername(anyString())).thenReturn(Optional.of(user));

        UserDto result = this.userService.getByUsername("testuser");
        assertNotNull(result);
        assertEquals("testuser", result.getUsername());
        verify(this.userRepository, times(1)).findByUsername("testuser");
    }

    @Test
    void getByEmail() {
        User user = MockData.user();
        when(this.userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        UserDto result = this.userService.getByEmail("test@mail.com");
        assertNotNull(result);
        assertEquals("test@mail.com", result.getEmail());
        verify(this.userRepository, times(1)).findByEmail("test@mail.com");
    }

    @Test
    void updateById() {
        UserDto request = UserDto.builder()
            .username("updatedUsername")
            .role("USER")
            .build();

        User user = MockData.user();
        when(this.userRepository.findById(1L)).thenReturn(Optional.of(user));

        user.setUsername("updatedUsername");
        when(this.userRepository.save(any(User.class))).thenReturn(user);

        UserDto result = this.userService.updateById(1L, request);

        assertNotNull(result);
        assertEquals("updatedUsername", result.getUsername());
        verify(this.userRepository, times(1)).save(any(User.class));
    }

    @Test
    void deleteById() {
        doNothing().when(this.userRepository).deleteById(1L);
        this.userService.deleteById(1L);
        verify(this.userRepository, times(1)).deleteById(1L);
    }

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;
}

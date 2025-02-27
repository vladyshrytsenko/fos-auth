package com.example.fosauth.model.dto;

import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.stream.Collectors;

@Getter @Setter
@AllArgsConstructor
@Builder
public class UserDto {

    private Long id;

    @Size(min = 6, max = 32, message = "invalid 'username' size")
    private String username;

    private String password;

    @Email(message = "invalid 'email' structure")
    private String email;

    @NotNull(message = "'role' should not be null")
    private String role;

    private String googleUserId;

    public static UserDto toDto(User user) {
        if (user == null) {
            return null;
        }

        return UserDto.builder()
            .id(user.getId())
            .username(user.getUsername())
            .password(user.getPassword())
            .email(user.getEmail())
            .role(user.getRole().name())
            .googleUserId(user.getGoogleUserId())
            .build();
    }

    public static List<UserDto> toDtoList(List<User> users) {
        if (users == null || users.isEmpty()) {
            return List.of();
        }

        return users.stream()
            .map(UserDto::toDto)
            .collect(Collectors.toList());
    }

    public static User toEntity(UserDto userDto) {
        if (userDto == null) {
            return null;
        }

        return User.builder()
            .username(userDto.getUsername())
            .password(userDto.getPassword())
            .email(userDto.getEmail())
            .role(Role.valueOf(userDto.getRole()))
            .googleUserId(userDto.getGoogleUserId())
            .build();
    }
}

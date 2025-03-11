package com.example.fosauth;

import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

public class MockData {

    public static User user() {
        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setUsername("testuser");
        user.setPassword("password");
        user.setRole(Role.USER);
        return user;
    }

    public static List<User> userList() {
        User user2 = new User();
        user2.setId(2L);
        user2.setEmail("test2@mail.com");
        user2.setUsername("testuser2");
        user2.setPassword("password");
        user2.setRole(Role.USER);

        return List.of(user(), user2);
    }
}

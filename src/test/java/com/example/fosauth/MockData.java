package com.example.fosauth;

import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.enums.Role;

import java.util.List;

public class MockData {

    public static User user() {
        User user = new User();
        user.setId(1L);
        user.setEmail("test@mail.com");
        user.setUsername("testuser");
        user.setFirstName("testuser_firstName");
        user.setLastName("testuser_lastName");
        user.setPassword("password");
        user.setRole(Role.USER);
        return user;
    }

    public static List<User> userList() {
        User user2 = new User();
        user2.setId(2L);
        user2.setEmail("test2@mail.com");
        user2.setUsername("testuser2");
        user2.setFirstName("testuser2_firstName");
        user2.setLastName("testuser2_lastName");
        user2.setPassword("password");
        user2.setRole(Role.USER);

        return List.of(user(), user2);
    }
}

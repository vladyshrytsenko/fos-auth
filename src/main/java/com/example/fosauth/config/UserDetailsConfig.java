package com.example.fosauth.config;

import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class UserDetailsConfig {

    private final UserService userService;

    @Bean
    public UserDetailsService getUserDetailsService() {
        return username -> {

            UserDto currentUser = null;
            if (!username.contains("@")) {
                UserDto byUsername = userService.getByUsername(username);
                if (byUsername != null) {
                    currentUser = userService.getByEmail(byUsername.getEmail());
                }
            } else {
                currentUser = userService.getByEmail(username);
            }
            return UserDto.toEntity(currentUser);
        };
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(getUserDetailsService());
        authenticationProvider.setPasswordEncoder(getPasswordEncoder());

        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}

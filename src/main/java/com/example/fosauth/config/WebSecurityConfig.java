package com.example.fosauth.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

//    private final AuthenticationFilter authenticationFilter;
//    private final AuthenticationProvider authenticationProvider;

//    @Value("${spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-id}")
//    private String clientId;
//
//    @Value("${spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-secret}")
//    private String clientSecret;

    @Bean //fixme
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));
//            .authorizeHttpRequests(authorize ->
//            authorize.anyRequest().authenticated()
//        );
        return http.formLogin(withDefaults()).build();
    }

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//            .authorizeHttpRequests(auth -> auth
//                .anyRequest().authenticated()
//            )
//            .oauth2Login(oauth2 -> oauth2
//                .successHandler((request, response, authentication) -> {
//                    String redirectUrl = "/";
//
//                    if (authentication instanceof OAuth2AuthenticationToken oauthToken) {
//                        String authProvider = oauthToken.getAuthorizedClientRegistrationId();
//
//                        if ("github".equals(authProvider)) {
//                            redirectUrl = "http://localhost:9000/api/users/auth/github";
//                        } else if ("google".equals(authProvider)) {
//                            redirectUrl = "http://localhost:9000/api/users/auth/google";
//                        }
//                    }
//
//                    response.sendRedirect(redirectUrl);
//                })
//            );
//        return http.build();
//    }

    @Bean
    public UserDetailsService users() {
        UserDetails user = User.builder()
            .username("admin")
            .password("{noop}password")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:8080", "http://localhost:4200"));
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}

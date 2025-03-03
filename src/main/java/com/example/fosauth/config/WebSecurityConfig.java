package com.example.fosauth.config;

import com.example.fosauth.config.properties.Client;
import com.example.fosauth.config.properties.CorsProperties;
import com.example.fosauth.config.properties.OAuthProperties;
import com.example.fosauth.exception.EntityNotFoundException;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({OAuthProperties.class, CorsProperties.class})
@RequiredArgsConstructor
public class WebSecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(AbstractHttpConfigurer::disable)
            .exceptionHandling(
                e -> e.authenticationEntryPoint(
                    new LoginUrlAuthenticationEntryPoint("/login")
                ))
            .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .formLogin(Customizer.withDefaults())
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("http://localhost:4200/menu", true)
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    Cookie cookie = new Cookie("JSESSIONID", null);
                    cookie.setHttpOnly(true);
                    cookie.setSecure(false);
                    cookie.setPath("/");
                    cookie.setMaxAge(0);

                    response.addCookie(cookie);
                    response.setStatus(HttpServletResponse.SC_OK);
                })
            )

            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers(HttpMethod.POST, "/api/users/auth/register").permitAll()
                .requestMatchers("/oauth2/token", "/oauth2/authorize").permitAll()
                .requestMatchers("/api/users/current-user").authenticated()
                .requestMatchers("/api/users").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        Client.Registration registration = this.authProperties.getClient().getRegistration();
        Client.Provider provider = this.authProperties.getClient().getProvider();

        // Google OAuth2 client registration
        ClientRegistration googleClientRegistration = ClientRegistration.withRegistrationId("Google")
            .clientId(registration.getGoogle().getClientId())
            .clientSecret(registration.getGoogle().getClientSecret())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(registration.getGoogle().getRedirectUri())
            .scope(OidcScopes.OPENID, OidcScopes.EMAIL, OidcScopes.PROFILE)
            .authorizationUri(provider.getGoogle().getAuthorizationUri())
            .tokenUri(provider.getGoogle().getTokenUri())
            .userInfoUri(provider.getGoogle().getUserInfoUri())
            .jwkSetUri(provider.getGoogle().getJwtSetUri())
            .build();

        // GitHub OAuth2 client registration
        ClientRegistration githubClientRegistration = ClientRegistration.withRegistrationId("Github")
            .clientId(registration.getGithub().getClientId())
            .clientSecret(registration.getGithub().getClientSecret())
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(registration.getGithub().getRedirectUri())
            .scope("read:user", "user:email")
            .authorizationUri(provider.getGithub().getAuthorizationUri())
            .tokenUri(provider.getGithub().getTokenUri())
            .userInfoUri(provider.getGithub().getUserInfoUri())
            .userNameAttributeName(provider.getGithub().getUserNameAttribute())
            .build();

        return new InMemoryClientRegistrationRepository(googleClientRegistration, githubClientRegistration);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer(UserRepository userRepository) {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                User principal = (User) context.getPrincipal().getPrincipal();

                context.getClaims().claims(claims -> {
                    String email = principal.getEmail();

                    User foundUser = userRepository.findByEmail(email)
                        .orElseThrow(() -> new EntityNotFoundException(User.class));

                    claims.put("user_id", foundUser.getId());
                    claims.put("email", foundUser.getEmail());
                    claims.put("role", foundUser.getRole().name());
                });
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        String jwtSetUri = this.authProperties.getAuthorizationserver().getClient().getOidcClient().getJwtSetUri();
        return NimbusJwtDecoder.withJwkSetUri(jwtSetUri)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(this.corsProperties.getAllowedOrigins());
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        grantedAuthoritiesConverter.setAuthoritiesClaimName("role");
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    private final OAuthProperties authProperties;
    private final CorsProperties corsProperties;

}

package com.example.fosauth.config;

import com.example.fosauth.config.util.AuthorizationServerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    //    @Value("${spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-id}")
    //    private String clientId;

    //    @Value("${spring.security.oauth2.authorizationserver.client.oidc-client.registration.client-secret}")
    //    private String clientSecret;

    private final AuthorizationServerProperties authorizationServerProperties;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.exceptionHandling(exceptions ->
            exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
            RegisteredClient.withId("test-client-id")
                .clientName("Test Client")
                .clientId("653875561290-jtd5p8sda5ulj7ul6s2dofkmq7k1neht.apps.googleusercontent.com")
                .clientSecret("{noop}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")
                .redirectUri("http://localhost:8080/login/oauth2/code")
                .scope("read.scope")
                .scope("write.scope")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // Opaque
                    .accessTokenTimeToLive(Duration.of(30, ChronoUnit.MINUTES))
                    .refreshTokenTimeToLive(Duration.of(120, ChronoUnit.MINUTES))
                    .reuseRefreshTokens(false)
                    .authorizationCodeTimeToLive(Duration.of(30, ChronoUnit.SECONDS))
                    .build())
                .build()
        );
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("http://localhost:9000")
            .tokenIntrospectionEndpoint("/oauth2/token-info")
            //            .issuer(authorizationServerProperties.getIssuerUrl())
            //            .tokenIntrospectionEndpoint(authorizationServerProperties.getIntrospectionEndpoint())
            .build();
    }
}

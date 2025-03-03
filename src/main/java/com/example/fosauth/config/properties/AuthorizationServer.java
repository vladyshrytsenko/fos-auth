package com.example.fosauth.config.properties;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class AuthorizationServer {

    private Client client = new Client();

    @Getter @Setter
    public static class Client {
        private OidcClient oidcClient = new OidcClient();

        @Getter @Setter
        public static class OidcClient {
            private Registration registration = new Registration();
            private String jwtSetUri;

            @Getter @Setter
            public static class Registration {
                private String clientId;
                private String clientSecret;
            }
        }
    }
}

package com.example.fosauth.config.properties;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class Client {

    private Registration registration = new Registration();
    private Provider provider = new Provider();

    @Getter @Setter
    public static class Registration {
        private Google google = new Google();
        private Github github = new Github();

        @Getter @Setter
        public static class Google {
            private String clientId;
            private String clientSecret;
            private String redirectUri;
        }

        @Getter @Setter
        public static class Github {
            private String clientId;
            private String clientSecret;
            private String redirectUri;
        }
    }

    @Getter @Setter
    public static class Provider {
        private Google google = new Google();
        private Github github = new Github();

        @Getter @Setter
        public static class Google {
            private String authorizationUri;
            private String tokenUri;
            private String userInfoUri;
            private String jwtSetUri;
        }

        @Getter @Setter
        public static class Github {
            private String authorizationUri;
            private String tokenUri;
            private String userInfoUri;
            private String userNameAttribute;
        }
    }
}

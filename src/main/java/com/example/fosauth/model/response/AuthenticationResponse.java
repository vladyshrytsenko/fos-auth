package com.example.fosauth.model.response;

import com.example.fosauth.model.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AuthenticationResponse {

    private String username;
    private String email;
    private Role role;

}

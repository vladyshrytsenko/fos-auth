package com.example.fosauth.model.response;

import com.example.fosauth.model.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class AuthenticationResponse {

    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private Role role;

}

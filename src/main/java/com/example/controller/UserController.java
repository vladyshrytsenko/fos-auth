package com.example.controller;

import com.example.model.dto.UserDto;
import com.example.model.entity.User;
import com.example.model.enums.Role;
//import com.example.model.request.GoogleAuthRequest;
import com.example.model.response.AuthenticationResponse;
import com.example.service.UserService;
import com.example.service.auth.AuthenticationService;
import com.example.service.auth.GoogleOAuthService;
import com.example.service.auth.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final AuthenticationService authenticationService;
    private final GoogleOAuthService googleOAuthService;
    private final JwtService jwtService;

    @GetMapping("/current-user")
    public ResponseEntity<UserDto> getCurrentUser() {
        try {
            UserDto userDto = this.userService.getCurrentUser();
            return ResponseEntity.ok(userDto);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

//    @CrossOrigin(origins = "http://localhost:4200")
//    @PostMapping("/auth/google")
//    public ResponseEntity<?> authenticateWithGoogle(@RequestBody GoogleAuthRequest googleAuthRequest) {
//        String idToken = googleAuthRequest.getToken();
//
//        String googleUserId = this.googleOAuthService.validateTokenAndGetUserId(idToken);
//        if (googleUserId == null) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid Google token");
//        }
//
//        UserDto userDto = this.userService.findByGoogleId(googleUserId);
//        if (userDto == null) {
//            this.userService.createUserFromGoogle(googleUserId, idToken);
//        }
//        return ResponseEntity.ok(new AuthenticationResponse(idToken));
//    }

    @GetMapping("/oauth/info")
    public ResponseEntity<UserDto> getUserInfo(@AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            String email = principal.getAttribute("email");
            String name = principal.getAttribute("name");

            UserDto userDto = userService.getByEmail(email);

            return ResponseEntity.ok(userDto);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {

        UserDto userDto = userService.getById(id);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<UserDto> getUserByUsername(@PathVariable String username) {

        UserDto userDto = userService.getByUsername(username);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {

        UserDto userDto = userService.getByEmail(email);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/role/{role}")
    public ResponseEntity<UserDto> getUserByRole(@PathVariable String role) {

        UserDto userDto = userService.findByRole(Role.valueOf(role));
        return ResponseEntity.ok(userDto);
    }

    @GetMapping
    public ResponseEntity<List<UserDto>> getAllUsers() {

        List<UserDto> users = userService.findAll();
        return ResponseEntity.ok(users);
    }

    @PostMapping("/auth/register")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody UserDto userRequestDto) {

        AuthenticationResponse registered = authenticationService.register(userRequestDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(registered);
    }

    @PostMapping("/auth/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody UserDto userRequestDto) {

        AuthenticationResponse authenticated = authenticationService.authenticate(userRequestDto);
        return ResponseEntity.status(HttpStatus.OK).body(authenticated);
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDto> updateUser(
        @PathVariable Long id,
        @RequestBody UserDto userRequestDto) {

        UserDto updatedUser = userService.update(id, userRequestDto);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {

        userService.delete(id);
        return ResponseEntity.noContent().build();
    }
}



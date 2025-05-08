package com.example.fosauth.controller;

import com.example.fosauth.model.dto.UserDto;
import com.example.fosauth.model.entity.User;
import com.example.fosauth.model.response.AuthenticationResponse;
import com.example.fosauth.service.UserService;
import com.example.fosauth.service.auth.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    @GetMapping("/current-user")
    public ResponseEntity<UserDto> getCurrentUser(
        @AuthenticationPrincipal Object principal) {

        if (principal instanceof Jwt jwt) {
            String username = jwt.getSubject();
            return ResponseEntity.ok(this.userService.getByUsername(username));

        } else if (principal instanceof OAuth2User oauthUser) {
            String email = oauthUser.getAttribute("email");
            return ResponseEntity.ok(this.userService.getByEmail(email));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserDto> getUserById(@PathVariable Long id) {

        UserDto userDto = this.userService.getById(id);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/username/{username}")
    public ResponseEntity<UserDto> getUserByUsername(@PathVariable String username) {

        UserDto userDto = this.userService.getByUsername(username);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping("/email/{email}")
    public ResponseEntity<UserDto> getUserByEmail(@PathVariable String email) {

        UserDto userDto = this.userService.getByEmail(email);
        return ResponseEntity.ok(userDto);
    }

    @GetMapping
    public ResponseEntity<?> getUsersList(Pageable pageable) {
        Page<User> userPage = this.userService.findAll(pageable);
        Page<UserDto> userDtoPage = userPage.map(UserDto::toDto);
        return ResponseEntity.ok(userDtoPage);
    }

    @PostMapping("/auth/register")
    public ResponseEntity<AuthenticationResponse> registerUser(@RequestBody UserDto userRequestDto) {

        AuthenticationResponse registered = this.authenticationService.register(userRequestDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(registered);
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDto> updateUser(
        @PathVariable Long id,
        @RequestBody UserDto userRequestDto) {

        UserDto updatedUser = this.userService.updateById(id, userRequestDto);
        return ResponseEntity.ok(updatedUser);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {

        this.userService.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    private final UserService userService;
    private final AuthenticationService authenticationService;
}

package com.example.fosauth.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class GoogleUserInfo {
    private String googleUserId;
    private String email;
    private String name;
}

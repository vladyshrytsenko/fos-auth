package com.example.fosauth.exception;

public class EntityNotFoundException extends RuntimeException {

    public EntityNotFoundException(Class<?> clazz) {
        super(clazz.getName().concat(" not found!"));
    }
}

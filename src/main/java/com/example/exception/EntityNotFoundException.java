package com.example.exception;

public class EntityNotFoundException extends RuntimeException {

    public EntityNotFoundException(Class<?> clazz) {
        super(clazz.getName().concat(" not found!"));
    }
}

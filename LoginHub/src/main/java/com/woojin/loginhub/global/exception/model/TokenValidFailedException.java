package com.woojin.loginhub.global.exception.model;

public class TokenValidFailedException extends RuntimeException {

    public TokenValidFailedException() {
        super("Failed to generate Token");
    }

    private TokenValidFailedException(String message) {
        super(message);
    }
}

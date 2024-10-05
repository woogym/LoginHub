package com.woojin.loginhub.global.exception.model;

import com.woojin.loginhub.global.exception.ErrorCode;

public class NotFoundException extends CustomException {
    public NotFoundException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}
package com.woojin.loginhub.global.exception.model;

import com.woojin.loginhub.global.exception.ErrorCode;

public class BadRequestException extends CustomException {
    public BadRequestException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}

package com.woojin.loginhub.global.exception.model;

import com.woojin.loginhub.global.exception.ErrorCode;

public class UnauthorizedException extends CustomException{

    public UnauthorizedException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}

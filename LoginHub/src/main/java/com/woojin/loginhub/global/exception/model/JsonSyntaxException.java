package com.woojin.loginhub.global.exception.model;

import com.woojin.loginhub.global.exception.ErrorCode;
import lombok.Getter;

@Getter
public class JsonSyntaxException extends CustomException{

    public JsonSyntaxException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}

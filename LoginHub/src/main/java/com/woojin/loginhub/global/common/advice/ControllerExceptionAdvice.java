package com.woojin.loginhub.global.common.advice;

import com.woojin.loginhub.global.common.dto.ApiResponseTemplate;
import com.woojin.loginhub.global.exception.ErrorCode;
import com.woojin.loginhub.global.exception.model.CustomException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Objects;

@RestControllerAdvice
@Component
@RequiredArgsConstructor
public class ControllerExceptionAdvice {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleMethodArgumentNotValidException(final MethodArgumentNotValidException e) {
        FieldError fieldError = Objects.requireNonNull(e.getFieldError());
        return ApiResponseTemplate.error(ErrorCode.VALIDATION_REQUEST_MISSING_EXCEPTION,
                String.format("%s. (%s)", fieldError.getDefaultMessage(), fieldError.getField()));
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleMissingRequestHeaderException(final MissingRequestHeaderException e) {
        return ApiResponseTemplate.error(ErrorCode.VALIDATION_REQUEST_HEADER_MISSING_EXCEPTION,
                String.format("%s. (%s)", ErrorCode.VALIDATION_REQUEST_HEADER_MISSING_EXCEPTION.getMessage(), e.getHeaderName()));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleMissingServletRequestParameterException(final MissingServletRequestParameterException e) {
        return ApiResponseTemplate.error(ErrorCode.VALIDATION_REQUEST_PARAMETER_MISSING_EXCEPTION,
                String.format("%s. (%s)", ErrorCode.VALIDATION_REQUEST_PARAMETER_MISSING_EXCEPTION.getMessage(), e.getParameterName()));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleHttpRequestMethodNotSupportedException(final HttpRequestMethodNotSupportedException e) {
        return ApiResponseTemplate.error(ErrorCode.REQUEST_METHOD_VALIDATION_EXCEPTION, e.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleAccessDeniedException(final AccessDeniedException e) {
        return ApiResponseTemplate.error(ErrorCode.ACCESS_DENIED_EXCEPTION, e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ApiResponseTemplate<Object>> handleException(final Exception e) {
        return ApiResponseTemplate.error(ErrorCode.INTERNAL_SERVER_EXCEPTION, "An unexpected error occurred: " + e.getMessage());
    }

    @ExceptionHandler(CustomException.class)
    protected ResponseEntity<ApiResponseTemplate<String>> handleCustomException(CustomException e) {
        return ApiResponseTemplate.error(e.getErrorCode(), e.getMessage());
    }
}

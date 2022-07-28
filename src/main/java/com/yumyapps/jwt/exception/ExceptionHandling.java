package com.yumyapps.jwt.exception;

import com.auth0.jwt.exceptions.TokenExpiredException;

import com.yumyapps.jwt.exception.exceptions.*;
import com.yumyapps.jwt.dto.http.HttpResponse;
import com.yumyapps.jwt.dto.http.HttpValidationResponse;
import com.yumyapps.jwt.dto.http.ValidatorResponseMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.persistence.NoResultException;
import javax.validation.ConstraintViolationException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static com.yumyapps.jwt.constants.Constants.*;
import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
@Validated
public class ExceptionHandling extends ResponseEntityExceptionHandler implements ErrorController {

    private final Logger LOGGER = LoggerFactory.getLogger(getClass());

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {

        HttpMethod supportedMethod = Objects.requireNonNull(ex.getSupportedHttpMethods()).iterator().next();
        var response = createHttpResponse(METHOD_NOT_ALLOWED, String.format(METHOD_IS_NOT_ALLOWED, supportedMethod));
        return new ResponseEntity<>(response, FORBIDDEN);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatus status, WebRequest request) {
        List<ValidatorResponseMessage> validatorResponseMessages = new ArrayList<>();
        ex.getBindingResult().getFieldErrors().forEach(
                (error) -> {
                    var errorDetails = new ValidatorResponseMessage(error.getField(), error.getDefaultMessage());
                    validatorResponseMessages.add(errorDetails);
                });
        var error = new HttpValidationResponse(status.value(), status, status.getReasonPhrase().toUpperCase(), VALIDATION_FAILED, validatorResponseMessages);
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);

    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException() {
        return createHttpResponse(BAD_REQUEST, ACCOUNT_DISABLED);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> badCredentialsException() {
        return createHttpResponse(BAD_REQUEST, INCORRECT_CREDENTIALS);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException() {
        return createHttpResponse(FORBIDDEN, NOT_ENOUGH_PERMISSION);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> lockedException(LockedException exception) {
        return createHttpResponse(UNAUTHORIZED, ACCOUNT_LOCKED);
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception) {
        return createHttpResponse(UNAUTHORIZED, exception.getMessage());
    }

    @ExceptionHandler(EmailExistException.class)
    public ResponseEntity<HttpResponse> emailExistException(EmailExistException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(UsernameExistException.class)
    public ResponseEntity<HttpResponse> usernameExistException(UsernameExistException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(EmailNotFoundException.class)
    public ResponseEntity<HttpResponse> emailNotFoundException(EmailNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(OldPasswordDenialException.class)
    public ResponseEntity<HttpResponse> oldPasswordDenial(OldPasswordDenialException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }
    @ExceptionHandler(PassowrdNotMatchException.class)
    public ResponseEntity<HttpResponse> PasswordNotMatch(PassowrdNotMatchException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

        @ExceptionHandler(value = {ConstraintViolationException.class})
        protected ResponseEntity<Object> handleConstraintViolation(ConstraintViolationException e, WebRequest request) {
            return handleExceptionInternal(e, e.getMessage(), new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
        }


    //
//// this exception belongs to application properties -- Throw the Exception If no Handler found
//
///*
//    @ExceptionHandler(NoHandlerFoundException.class)
//    public ResponseEntity<HttpResponse> methodNotSupportedException(NoHandlerFoundException exception) {
//        System.out.println("No Handler");
//        return createHttpResponse(BAD_REQUEST, "This Page Was Not Found");
//    }
//*/
//
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<HttpResponse> userNotFoundException(UserNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

   /* @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse> internalServerErrorException(Exception exception) {
        LOGGER.error(exception.getMessage());
        return createHttpResponse(INTERNAL_SERVER_ERROR, INTERNAL_SERVER_ERROR_MSG);
    }*/

    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> notFoundException(NoResultException exception) {
        LOGGER.error(exception.getMessage());
        return createHttpResponse(NOT_FOUND, exception.getMessage());
    }

    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(
                new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                        message), httpStatus);
    }

    /*@RequestMapping(ERROR_PATH)
    public ResponseEntity<HttpResponse> notFound404() {
        return createHttpResponse(NOT_FOUND, "There is no mapping for this URL");
    }*/


}

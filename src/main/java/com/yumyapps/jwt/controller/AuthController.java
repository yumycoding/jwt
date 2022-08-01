package com.yumyapps.jwt.controller;


import com.yumyapps.jwt.constants.Constants;
import com.yumyapps.jwt.dto.TokenInformation;
import com.yumyapps.jwt.dto.UserRegistrationDto;
import com.yumyapps.jwt.dto.UserUpgradeDto;
import com.yumyapps.jwt.dto.http.HttpResponse;
import com.yumyapps.jwt.exception.ExceptionHandling;
import com.yumyapps.jwt.exception.exceptions.EmailExistException;
import com.yumyapps.jwt.exception.exceptions.UserNotFoundException;
import com.yumyapps.jwt.exception.exceptions.UsernameExistException;
import com.yumyapps.jwt.jwtutil.JwtTokenProvider;
import com.yumyapps.jwt.models.User;
import com.yumyapps.jwt.service.AuthService;
import com.yumyapps.jwt.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

import static com.yumyapps.jwt.constants.Constants.*;
import static org.springframework.http.HttpStatus.*;

@Slf4j
@RestController
@RequestMapping(path = "/v1/auth")
@RequiredArgsConstructor
@Api(tags = {Constants.AUTH_API_TAG})
public class AuthController extends ExceptionHandling {


    private final UserService userService;

    private final JwtTokenProvider jwtTokenProvider;

    private final AuthService authService;


    @ApiOperation(value = "Add a new user", notes = "Add a new user information into the system", response = UserRegistrationDto.class)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The User saved Successfully"),
            @ApiResponse(responseCode = "201", description = "The User Created Successfully"),
            @ApiResponse(responseCode = "500", description = "Successfully retrieved list"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PostMapping(path = "/register")
    public ResponseEntity<String> registerNewUser(@ApiParam(value = "Please provide the firstName ,lastName ,username, password , email", required = true)
                                                  @Valid @RequestBody UserRegistrationDto user) throws UserNotFoundException, EmailExistException, UsernameExistException {

            User registeredUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail(), user.getPassword(), user.getConformPassword());
        return new ResponseEntity<>("Account is registered Successfully with username " + registeredUser.getUsername() + " , Please Login! ", null, OK);
    }

    @ApiOperation(value = "User login", notes = "Add username and password to login into the system", response = TokenInformation.class)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "The User login Successfully"),
            @ApiResponse(responseCode = "201", description = "The User login Successfully"),
            @ApiResponse(responseCode = "500", description = "Internal Server Error"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PostMapping("/login")
    public ResponseEntity<TokenInformation> login(@ApiParam(value = "Please Enter username")
                                                  @RequestParam(value = "username") String username,
                                                  @ApiParam(value = "Please Enter password")
                                                  @RequestParam(value = "password") String password) {

        TokenInformation tokenInformation = authService.authenticateUser(username, password);
        return new ResponseEntity<>(tokenInformation, tokenInformation.getHeader(), OK);

    }


    @ApiOperation(value = "User Information", notes = "Add a new user information into the system", response = User.class)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Information fetched successfully"),
            @ApiResponse(responseCode = "201", description = "Information fetched successfully"),
            @ApiResponse(responseCode = "500", description = "Internal Server Error"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:read')")
    @GetMapping(path = "/me")
    public ResponseEntity<User> currentUserInfo(@ApiParam(hidden = true, value = "Please do not pass the token if you are already authorized")
                                                @RequestHeader(value = "Authorization", required = false) String authToken) {
        var token = authToken.substring(TOKEN_PREFIX.length());
        String user = jwtTokenProvider.getSubject(token);
        User userObject = userService.findUserByUsername(user);
        return new ResponseEntity<>(userObject, null, OK);
    }


    @ApiOperation(value = "Update an existing User", notes = "Update User by passing in the User information like first name or last name", response = UserUpgradeDto.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The user was updated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAnyAuthority('user:create')")
    @PostMapping("/update")
    public ResponseEntity<User> updateUserInfo(UsernamePasswordAuthenticationToken token,
                                               @ApiParam(value = "User can update Firstname and Lastname", required = true)
                                               @Valid @RequestBody UserUpgradeDto user) {

        User updatedUser = authService.updateUserInfo(user, token);
        return new ResponseEntity<>(updatedUser, OK);
    }


    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase()), httpStatus);
    }

}

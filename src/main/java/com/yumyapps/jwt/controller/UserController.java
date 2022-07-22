package com.yumyapps.jwt.controller;


import com.yumyapps.jwt.constants.Constants;
import com.yumyapps.jwt.dto.TokenInformation;
import com.yumyapps.jwt.dto.UserRegistrationDto;
import com.yumyapps.jwt.exception.ExceptionHandling;
import com.yumyapps.jwt.exception.exceptions.EmailExistException;
import com.yumyapps.jwt.exception.exceptions.UserNotFoundException;
import com.yumyapps.jwt.exception.exceptions.UsernameExistException;
import com.yumyapps.jwt.jwtutil.JwtTokenProvider;
import com.yumyapps.jwt.models.User;
import com.yumyapps.jwt.models.http.HttpResponse;
import com.yumyapps.jwt.security.UserPrincipal;
import com.yumyapps.jwt.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;


import static com.yumyapps.jwt.constants.Constants.*;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;


@RestController
@Api(tags = {Constants.API_TAG})
@RequestMapping(path = "/v1/users")
public class UserController extends ExceptionHandling {

    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

    public UserController(UserService userService, AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @ApiOperation(value = "User login", notes = "Add username and password to login into the system", response = User.class)
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
        authenticate(username, password);
        var loginUser = userService.findUserByUsername(username);
        var userPrincipal = new UserPrincipal(loginUser);
        var jwtHeader = getJwtHeader(userPrincipal);
        var information = getJwtInfo(userPrincipal);
        return new ResponseEntity<>(information, jwtHeader, OK);
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
    public ResponseEntity<User> currentUserInfo(@ApiParam(value = "Please do not pass the token if you are already authorized")
                                                @RequestHeader(value = "Authorization", required = false) String authToken) {
        var token = authToken.substring(TOKEN_PREFIX.length());
        String user = jwtTokenProvider.getSubject(token);
        User userObject = userService.findUserByUsername(user);
        return new ResponseEntity<>(userObject, null, OK);
    }

    private void authenticate(String username, String password) {
        authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }


    @ApiOperation(value = "Add a new user", notes = "Add a new user information into the system", response = User.class)
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
    public ResponseEntity<String> registerNewUser(@ApiParam(value = "Please provide the firstName ,lastName ,username, password , email", required = true) @Valid @RequestBody UserRegistrationDto user) throws UserNotFoundException, EmailExistException, UsernameExistException {
        User registeredUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail(), user.getPassword());
        return new ResponseEntity<>("Account is registered Successfully with username " + registeredUser.getUsername() + " , Please Login! ", null, OK);
    }


    @PreAuthorize("hasAnyAuthority('user:create','user:update')")
    @PostMapping(path = "/unlock")
    public String unlockUserAccount(@RequestParam(name = "email") String email) {
        userService.unlockAccount(email);
        return "account associated with email " + email + " unlock successfully";
    }

    @ApiOperation(value = "Update an existing User", notes = "Update User by passing in the User information with an existing username and email address", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The user was updated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAnyAuthority('user:update')")
    @PostMapping("/update")
    public ResponseEntity<User> updateUserInfo(@ApiParam(value = "Please enter  existing username")
                                               @RequestParam("currentUsername") String currentUsername,
                                               @ApiParam(value = "Please enter  Firstname")
                                               @RequestParam(value = "firstName") String firstName,
                                               @ApiParam(value = "Please enter  Lastname")
                                               @RequestParam(value = "lastName") String lastName,
                                               @ApiParam(value = "Please enter desired username")
                                               @RequestParam("username") String username,
                                               @ApiParam(value = "Please enter desired email address")
                                               @RequestParam("email") String email,
                                               @ApiParam(value = "Please set the user role")
                                               @RequestParam(value = "role") String role,
                                               @ApiParam(value = "Set the Account Active or disable by entering true/false")
                                               @RequestParam(value = "isActive") String isActive,
                                               @ApiParam(value = "Set the Account lock or unlock by entering true/false")
                                               @RequestParam(value = "isNonLocked") String isNonLocked) throws IOException {
        User updatedUser = userService.updateUser(currentUsername, firstName, lastName, username, email, role, Boolean.parseBoolean(isNonLocked), Boolean.parseBoolean(isActive));
        return new ResponseEntity<>(updatedUser, OK);
    }


    @ApiOperation(value = "Update an existing User Password", notes = "Update User Password by passing in the User information with an existing email address and new password", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The password was updated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:read')")
    @PostMapping("/updatePassword")
    public String updateUserPassword(@ApiParam(value = "Enter existing email")
                                     @RequestParam("email") String email,
                                     @ApiParam(value = "Enter a new password")
                                     @RequestParam("password") String password,
                                     @ApiParam(value = "Do not enter token if you already authorized ")
                                     @RequestHeader(value = "Authorization", required = false) String authToken
    ) {

        var token = authToken.substring(TOKEN_PREFIX.length());
        if (verifyUser(token, email)) {
            userService.resetPassword(email, password);
            return "Password is Changed";
        } else
            throw new UserNotFoundException("Invalid Email Address " + email);
    }

    @ApiOperation(value = "Find an user by email address", notes = "Retrieve User info by passing the email address", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The User against email address"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:update')")
    @GetMapping("/find/{username}")
    public ResponseEntity<User> getUserByUsername(@ApiParam(value = "Enter a username")
                                                  @PathVariable(value = "username") String username) {
        User user = userService.findUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException("Invalid User name");
        }
        return new ResponseEntity<>(user, OK);
    }

    @ApiOperation(value = "Delete the user by username", notes = "Delete the user by passing username")
    @ApiResponses({@ApiResponse(responseCode = "204", description = "The User was deleted successfully"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @DeleteMapping("/delete/{username}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@ApiParam(value = "please enter username here")
                                                   @PathVariable("username") String username) throws IOException {
        userService.deleteUser(username);
        return response(NO_CONTENT, USER_DELETED_SUCCESSFULLY);
    }


    /*@GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }
*/
    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase()), httpStatus);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private boolean verifyUser(String token, String email) {
        String subjectUsername = jwtTokenProvider.getSubject(token);
        var emailBySubjectUsername = userService.findEmailBySubjectUsername(subjectUsername);
        return emailBySubjectUsername.equals(email);
    }

    private TokenInformation getJwtInfo(UserPrincipal userPrincipal) {
        TokenInformation tokenInfo = new TokenInformation();
        var token = jwtTokenProvider.generateJwtToken(userPrincipal);
        var expiryDate = jwtTokenProvider.getTokenExpiryDate(token);
        var totalLifeTime = expiryDate.getTime() - new Date().getTime();
        var days = TimeUnit.MILLISECONDS.toDays(totalLifeTime);

        tokenInfo.setToken(token);
        tokenInfo.setExpiryTime(days + " Days");
        return tokenInfo;
    }


}

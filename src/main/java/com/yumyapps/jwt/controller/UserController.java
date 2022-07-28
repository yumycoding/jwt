package com.yumyapps.jwt.controller;


import com.yumyapps.jwt.constants.Constants;
import com.yumyapps.jwt.dto.UserRegistrationDto;
import com.yumyapps.jwt.dto.http.HttpResponse;
import com.yumyapps.jwt.exception.ExceptionHandling;
import com.yumyapps.jwt.exception.exceptions.EmailExistException;
import com.yumyapps.jwt.exception.exceptions.UserNotFoundException;
import com.yumyapps.jwt.exception.exceptions.UsernameExistException;
import com.yumyapps.jwt.models.User;
import com.yumyapps.jwt.service.UserService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.io.IOException;
import java.util.List;

import static com.yumyapps.jwt.constants.Constants.USER_DELETED_SUCCESSFULLY;
import static org.springframework.http.HttpStatus.NO_CONTENT;
import static org.springframework.http.HttpStatus.OK;


@RestController
@Api(tags = {Constants.API_TAG})
@RequestMapping(path = "/v1/users")
public class UserController extends ExceptionHandling {

    private final UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;

    }


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
    public ResponseEntity<String> registerNewUser(@ApiParam(value = "Please provide the firstName ,lastName ,username, password , email", required = true) @Valid @RequestBody UserRegistrationDto user) throws UserNotFoundException, EmailExistException, UsernameExistException {
        User registeredUser = userService.register(user.getFirstName(), user.getLastName(), user.getUsername(), user.getEmail(), user.getPassword());
        return new ResponseEntity<>("Account is registered Successfully with username " + registeredUser.getUsername() + " , Please Login! ", null, OK);
    }


    @ApiOperation(value = "Find the user by username", notes = "Retrieve User info by passing the username", response = User.class)
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

    @ApiOperation(value = "Unlock the user with email address", notes = "Unlock Users")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The users list generated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAnyAuthority('user:create','user:update')")
    @PostMapping(path = "/unlock")
    public String unlockUserAccount(@ApiParam(value = "Enter email to unlock the user") @RequestParam(name = "email") String email) {
        userService.unlockAccount(email);
        return "account associated with email " + email + " unlock successfully";
    }


    @ApiOperation(value = "View all registered users in database", notes = "Registered Users List")
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The users list generated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:create')")
    @GetMapping("/list")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase()), httpStatus);
    }


}

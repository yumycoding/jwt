package com.yumyapps.jwt.controller;


import com.yumyapps.jwt.constants.Constants;
import com.yumyapps.jwt.dto.PasswordUpdateDto;
import com.yumyapps.jwt.dto.http.HttpResponse;
import com.yumyapps.jwt.exception.ExceptionHandling;
import com.yumyapps.jwt.exception.exceptions.EmailNotFoundException;
import com.yumyapps.jwt.exception.exceptions.UserNotFoundException;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Email;
import java.io.IOException;
import java.util.List;

import static com.yumyapps.jwt.constants.Constants.*;
import static org.springframework.http.HttpStatus.*;


@RestController
@Api(tags = {Constants.API_TAG})
@RequestMapping(path = "/v1/users")
public class UserController extends ExceptionHandling {

    private final UserService userService;


    public UserController(UserService userService) {
        this.userService = userService;

    }


    @ApiOperation(value = "Update an existing User Password", notes = "Update  Password by passing old password and new password", response = PasswordUpdateDto.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The password was updated successfully"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PostMapping(path = "/update-password")
    public ResponseEntity<HttpResponse> updatePassword(@ApiParam(value = "Please Ignore this bug", name = "token", hidden = true) UsernamePasswordAuthenticationToken token,
                                                       @ApiParam(value = "Please provide old password and new password for update the password", required = true)
                                                       @Valid @RequestBody PasswordUpdateDto updateDto

    ) {

        boolean result = userService.updatePassword(token, updateDto);

        return result ? response(CREATED, PASSWORD_CHANGED_SUCCESSFUL)
                : response(BAD_REQUEST, INTERNAL_SERVER_ERROR_MSG);
    }


  /*  @ApiOperation(value = "Find the user by username", notes = "Retrieve User info by passing the username", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The User against email address"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:update')")
    @GetMapping(path = "/find/name/{username}")
    public ResponseEntity<User> findByUsername(@ApiParam(value = "Enter a username")
                                               @PathVariable(name = "username") String username) {
        User user = userService.findUserByUsername(username);
        if (user == null) {
            throw new UserNotFoundException("Invalid User name");
        }
        return new ResponseEntity<>(user, OK);
    }
*/

    @ApiOperation(value = "Find the user by ID", notes = "Retrieve User info by passing the user Id", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The User against User Id"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:update')")
    @GetMapping(path = "/find/id/{uuid}")
    public ResponseEntity<User> findByUUID(@ApiParam(value = "Enter user id")
                                           @PathVariable(name = "uuid") String UUID) {
        User user = userService.findUserByUserId(UUID);
        if (user == null) {
            throw new UserNotFoundException("Invalid User name");
        }
        return new ResponseEntity<>(user, OK);
    }


    @ApiOperation(value = "Find the user by email", notes = "Retrieve User info by passing the user email", response = User.class)
    @ApiResponses({@ApiResponse(responseCode = "200", description = "The User against User email"),
            @ApiResponse(responseCode = "400", description = "The request is malformed or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @PreAuthorize("hasAuthority('user:update')")
    @GetMapping(path = "/find/email/{email}")
    public ResponseEntity<User> findByEmail(@ApiParam(value = "Enter user email")
                                            @PathVariable(name = "email") @Email String email) {

        User user = userService.findUserByEmail(email);
        if (user == null) {
            throw new EmailNotFoundException("Invalid Email Address");
        }
        return new ResponseEntity<>(user, OK);
    }


    @ApiOperation(value = "Delete the user by id", notes = "Delete the user by passing user id")
    @ApiResponses({@ApiResponse(responseCode = "204", description = "The User was deleted successfully"),
            @ApiResponse(responseCode = "400", description = "The request is bad or invalid"),
            @ApiResponse(responseCode = "404", description = "The resource URL was not found on the server"),
            @ApiResponse(responseCode = "500", description = "An internal server error occurred"),
            @ApiResponse(responseCode = "403", description = "You are not authorized. Please authenticate and try again"),
            @ApiResponse(responseCode = "401", description = "You don't have permission to this resource")
    })
    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@ApiParam(value = "please enter username here")
                                                   @PathVariable("id") String id) throws IOException {
        userService.softDeleteByUUID(id);
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

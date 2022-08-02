package com.yumyapps.jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yumyapps.jwt.validator.StrictPassword;
import com.yumyapps.jwt.validator.ValidEmail;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.*;

@Data
public class UserRegistrationDto {

    @NotNull
    @NotEmpty(message = "first name should not be empty")
    @Size(min = 3, max = 100, message = "firstname should contain more than two characters")
    @ApiModelProperty(value = "Please enter your fist name", example = "John")
    private String firstName;

    @NotNull
    @NotEmpty(message = "last name should not be empty")
    @Size(min = 3, max = 100, message = "lastname should contain more than two characters")
    @ApiModelProperty(value = "Please enter your last name", example = "Dao")
    private String lastName;

    @NotNull
    @NotEmpty(message = "username cannot be empty, please enter a valid username")
    @Size(min = 3, max = 100, message = "username should contain more than two characters")
    @ApiModelProperty(value = "Please enter desired username", example = "johndao")
    private String username;

    @NotEmpty
    @StrictPassword
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @NotEmpty
    @StrictPassword
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String conformPassword;

    @NotEmpty(message = "lastname should contain more than two characters")
    @ValidEmail
    @ApiModelProperty(value = "please Enter your email address", example = "john@yumyapps.com")
    private String email;


}

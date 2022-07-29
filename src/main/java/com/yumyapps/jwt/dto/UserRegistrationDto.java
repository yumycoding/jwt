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
    @Size(min = 3, max = 100)
    @ApiModelProperty(value = "Please enter your fist name", example = "John")
    private String firstName;

    @NotNull
    @Size(min = 3, max = 100)
    @ApiModelProperty(value = "Please enter your last name", example = "Dao")
    private String lastName;

    @NotNull
    @Size(min = 3, max = 100)
    @ApiModelProperty(value = "Please enter desired username", example = "johndao")
    private String username;

    @NotEmpty
    @StrictPassword
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;


    @NotEmpty
    @StrictPassword
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String matchingPassword;

    @NotEmpty
    @ValidEmail
    @ApiModelProperty(value = "please Enter your email address", example = "john@yumyapps.com")
    private String email;


}

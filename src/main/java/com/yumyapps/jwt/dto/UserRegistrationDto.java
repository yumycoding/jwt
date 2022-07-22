package com.yumyapps.jwt.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
public class UserRegistrationDto {

    @NotNull
    @Size(min = 3, max = 50)
    @ApiModelProperty(value = "Please enter your fist name", example = "John")
    private String firstName;

    @NotNull
    @Size(min = 3, max = 50)
    @ApiModelProperty(value = "Please enter your last name", example = "Dao")
    private String lastName;

    @NotNull
    @Size(min = 5, max = 50)
    @ApiModelProperty(value = "Please enter desired username", example = "johndao")
    private String username;

    @NotNull
    @NotEmpty
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @NotNull
    @Email
    @ApiModelProperty(value = "please Enter your email address", example = "john@yumyapps.com")
    private String email;


}

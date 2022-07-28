package com.yumyapps.jwt.dto;


import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.*;

@Data
public class UserUpgradeDto {

//    @NotEmpty
//    @NotNull
//    @Size(min = 3, max = 100)
//    @ApiModelProperty(value = "Please enter your current name", example = "JohnDao")
//    private String CurrentUsername;
//
//    @NotEmpty
//    @Email
//    private String newEmailAddress;

    @NotNull
    @Size(min = 3, max = 100)
    @ApiModelProperty(value = "Please enter your new fist name", example = "John")
    private String newFirstName;

    @NotNull
    @Size(min = 3, max = 100)
    @ApiModelProperty(value = "Please enter your new last name", example = "Dao")
    private String newLastName;

//    @Pattern(regexp = "^(true|false)$", message = "please enter true or false")
//    @ApiModelProperty(value = "Please enter true or false", example = "true / false")
//    private String isActive;
//
//
//    @Pattern(regexp = "^(true|false)$", message = "please enter true or false")
//    @ApiModelProperty(value = "Please enter true or false", example = "true / false")
//    private String isNotLocked;
//
//
//    @ApiModelProperty(value = "Please enter new Role", example = "ROLE_USER")
//    private String newRole;


}

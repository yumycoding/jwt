package com.yumyapps.jwt.dto;

import com.yumyapps.jwt.validator.StrictPassword;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

// This Dto Used for password update process by user.

@Data
public class PasswordUpdateDto {

    @NotNull
    @NotEmpty
    private String oldPassword;

    @NotEmpty
    @StrictPassword
    private String newPassword;

    @NotEmpty
    @StrictPassword
    private String conformPassword;

}

package com.yumyapps.jwt.dto;

import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

// This Dto Used for password update process by user.

@Data
public class PasswordUpdateDto {

    @NotNull
    @NotEmpty
    @Size(min = 3)
    private String oldPassword;
    @NotEmpty
    @Size(min = 3)
    private String newPassword;
    @NotEmpty
    @Size(min = 3)
    private String matchingPassword;

}

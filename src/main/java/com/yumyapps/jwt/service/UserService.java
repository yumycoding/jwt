package com.yumyapps.jwt.service;

import com.yumyapps.jwt.dto.PasswordUpdateDto;
import com.yumyapps.jwt.exception.exceptions.*;
import com.yumyapps.jwt.models.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

public interface UserService {

    User register(String firstName, String lastName, String username, String email, String password,String retypePassword) throws UserNotFoundException, UsernameExistException, EmailExistException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User findUserByUserId(String id);
    void unlockAccount(String email);

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername,
                    String newEmail, String role, boolean isNonLocked, boolean isActive)
            throws UserNotFoundException, UsernameExistException, IOException, NotAnImageFileException, EmailExistException;



    void deleteUser(Long id) throws IOException;

    void softDeleteByUUID(String username) throws IOException;

    void resetPassword(String email, String password) throws EmailNotFoundException, UserNotFoundException;

    boolean updatePassword(UsernamePasswordAuthenticationToken token, PasswordUpdateDto updateDto);

    String findEmailBySubjectUsername(String username);

    String getPasswordByUserName(String username);

}

package com.yumyapps.jwt.repository;

import com.yumyapps.jwt.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {


    Optional<User> findUserByUsername(String username);

    Optional<User> findUserByEmail(String email);

    @Query("select u.email from User u where u.username =:username")
    String getEmailByUsername(String username);

    @Query("select u.password from User u where u.username =:username")
    String getPasswordByUsername(String username);

    Optional<User> findByUserId(@NonNull String userId);


}

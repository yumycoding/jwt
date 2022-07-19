package com.yumyapps.jwt.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "user_domain")
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false, updatable = false)
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private Long id;
    private String userId;

    @NotNull
    @Size(min = 3, max = 50)
    @ApiModelProperty(value = "Please enter your fist name", example = "John")
    private String firstName;

    @NotNull
    @Size(min = 3, max = 50)
    @ApiModelProperty(value = "Please enter your last name", example = "Dao")
    private String lastName;

    @Size(min = 5, max = 50)
    @ApiModelProperty(value = "Please enter desired username", example = "johndao")
    private String username;

    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

    @NotNull
    @Email
    @ApiModelProperty(value = "please Enter your email address", example = "john@yumyapps.com")
    private String email;
    private Date lastLoginDate;
    private Date lastLoginDateDisplay;
    @CreationTimestamp
    private Date joinDate;
    private String role; //ROLE_USER{ read, edit }, ROLE_ADMIN {delete}
    private String[] authorities;
    private boolean isActive;
    private boolean isNotLocked;

}

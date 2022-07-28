package com.yumyapps.jwt.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpHeaders;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenInformation {

    private String token;
    private String expiryTime;
    @JsonIgnore
    private HttpHeaders header;

}

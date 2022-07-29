package com.yumyapps.jwt.constants;

public class Constants {

    //Authority Constants
    public static final String[] USER_AUTHORITIES = {"user:read"};
    public static final String[] HR_AUTHORITIES = {"user:read", "user:update"};
    public static final String[] MANAGER_AUTHORITIES = {"user:read", "user:update"};
    public static final String[] ADMIN_AUTHORITIES = {"user:read", "user:create", "user:update"};
    public static final String[] SUPER_ADMIN_AUTHORITIES = {"user:read", "user:create", "user:update", "user:delete"};
    // Constraint Validation

    public static final String INVALID_PASSWORD = "The given password is invalid, please add 2 numeric and one special character like '%s'";
    public static final String INVALID_EMAIL = "The given email is invalid, must be a well-formed email address";

    // Exception Constants
    public static final String VALIDATION_FAILED = "Data Validation occurred.";
    public static final String ACCOUNT_LOCKED = "Your account has been locked. Please contact administration";
    public static final String METHOD_IS_NOT_ALLOWED = "This request method is not allowed on this endpoint. Please send a '%s' request";
    public static final String INTERNAL_SERVER_ERROR_MSG = "An error occurred while processing the request, invalid inputs";
    public static final String INCORRECT_CREDENTIALS = "Username / password incorrect. Please try again";
    public static final String ACCOUNT_DISABLED = "Your account has been disabled. If this is an error, please contact administration";
    public static final String OLD_PASSWORD_DENIED = "The new Password must be different from the old Password";
    public static final String PASSWORD_DO_NOT_MATCH = "Password Does Not Match, please retype the password";
    public static final String PASSWORD_CHANGED_SUCCESSFUL = "Password updated successfully";
    public static final String ERROR_PROCESSING_FILE = "Error occurred while processing file";
    public static final String NOT_ENOUGH_PERMISSION = "You do not have enough permission";
    public static final String ERROR_PATH = "/error";


    //Security Constants
    public static final long EXPIRATION_TIME = 432_000_000; // 5 days expressed in milliseconds
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token cannot be verified";
    public static final String GET_YUMY_PVT_LTD = "YumyApps Developers, Private Limited";
    public static final String GET_YUMY_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You do not have permission to access this page";
    public static final String OPTIONS_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/v1/auth/login", "/v1/auth/register", "/v1/users/image/**",
            "/graphiql/**", "/graphql/**", "/swagger-ui/**", "/v2/api-docs", "/swagger-resources/**", "/webjars/**"};
    //public static final String[] PUBLIC_URLS = {"**"};
    public static final String[] OPEN_API_URLS = {"/v2/api-docs", "/swagger-resources/**", "/swagger-ui/**", "/webjars/**"};

    // Swagger Documentation Constants

    public static final String SECURITY_REFERENCE = "Token Access";
    public static final String AUTHORIZATION_DESCRIPTION = "Full API Permission";
    public static final String AUTHORIZATION_SCOPE = "Unlimited";
    public static final String CONTACT_EMAIL = "contact@yummyapps.com";
    public static final String CONTACT_URL = "https://";
    public static final String CONTACT_NAME = "Login API Support";
    public static final String API_TITLE = "User Login Management open API";
    public static final String API_DESCRIPTION = "User Login API";
    public static final String TERM_OF_SERVICE = "Term of service will go here";
    public static final String API_VERSION = "1.1";
    public static final String LICENSE = "Apache License 2.1.0";
    public static final String LICENSE_URL = "https://www.apache.org/licenses/LICENSE-2.0";
    public static final String SECURE_PATH = "/*/.*";
    public static final String API_TAG = "User API Service";
    public static final String AUTH_API_TAG = "Auth API Service";

    // User implementation Constants
    public static final String USERNAME_ALREADY_EXISTS = "Username already exists";
    public static final String EMAIL_ALREADY_EXISTS = "Email already exists";
    public static final String NO_USER_FOUND_BY_USERNAME = "No user found by username: ";
    public static final String FOUND_USER_BY_USERNAME = "Returning found user by username: ";
    public static final String NO_USER_FOUND_BY_EMAIL = "No user found for email: ";
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully";


}

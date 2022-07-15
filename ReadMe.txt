

JwtTokenProvider Class in jwtutil Packed is responsible for doing all operations like authentication and authorization.
there are three filters are configured in filter package which performs actions according to the failure or successful authentication.
there are two listeners in listeners package which controls bruteforce attack and lock the user after 5 unsuccessful attempts.
In exception package ExceptionHandling.class handles input validations and Other possibles exceptions and return meaningful message with Error codes.
LoginAttemptService Class helps to store the login attempts.



**********User Registration Process**********
http://localhost:8080/users/register
{
        "firstName" : "Umer",
        "lastName": "Khan",
        "username": "umerkhan",
        "password": "foo",
        "email": "umer@gmil.com"

}

**********User Login Process**************
http://localhost:8080/users/login
{
"username" : "faisal",
"password" : "foo"
}


************Update User **************************

http://localhost:8080/users/update?currentUsername=umerkhan&firstName=Ummer&lastName=Ali&username=umerkhan&email=umner@gmail.com&role=ROLE_ADMIN&isActive=true&isNonLocked=true

************** Unlock User **********************
http://localhost:8080/users/unlock?email=faisal@gmail.com


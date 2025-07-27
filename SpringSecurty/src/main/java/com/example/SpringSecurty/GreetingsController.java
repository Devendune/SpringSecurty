package com.example.SpringSecurty;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController
{
    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/hello")
    public String getHelle()
    {
        return "Hello Buddy";
    }

    @PreAuthorize("/hasRole('USER')")
    @GetMapping("/user")
    public String userEndPoint()
    {
        return "Hello User buddy";
    }

    @GetMapping("/admin")
    public String adminEndPoint()
    {
        return "Hello Admin bro";
    }


}

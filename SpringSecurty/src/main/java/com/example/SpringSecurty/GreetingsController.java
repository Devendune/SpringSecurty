package com.example.SpringSecurty;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController
{

    @GetMapping("/")
    public String getHelle()
    {
        return "Hello Buddy";
    }

}

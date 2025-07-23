package com.example.securitydemo.jwt;

import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils
{
    //Getting JWT from header
    private int jwtExpirationMs=30000;
    private static final Logger logger= LoggerFactory.getLogger(JwtUtils.class);
    public String getJwtFromHeader(HttpServletRequest httpServletRequest)
    {
        String bearerToken=httpServletRequest.getHeader("Authorization");
        if(bearerToken!=null && bearerToken.startsWith("Bearer "))
        {
            return bearerToken.substring(7);
        }
        return null;
    }
    //Generating Token from username
    //We are here generating a Token to send to client after successful authentication
    // so that it can be used for authenticating by client.
    public String generateTokenFromUserName(UserDetails userDetails)
    {
        String username=userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date().getTime()+jwtExpirationMs)))
                .signWith(key)
                .compact();
    }


}

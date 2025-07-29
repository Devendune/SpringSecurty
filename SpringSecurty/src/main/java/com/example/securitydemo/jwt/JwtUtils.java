package com.example.securitydemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils
{
    //Getting JWT from header
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;
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
                .signWith(key())
                .compact();
    }

    //Getting Username from Token
    public String generateUserNameFromToken(String token)
    {
        return Jwts.parser()
                .verifyWith((SecretKey)key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public Key key()
    {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public boolean validateJwtToken(String authToken)
    {
        try
        {
            System.out.println("Validating the token");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
            return true;

        }
        catch(MalformedJwtException exception)
        {
            logger.error("Invalid JWT Token: {}", exception.getMessage());
        }
        catch (ExpiredJwtException exception)
        {
            logger.error("JWT Token has expired: {}", exception.getMessage());
        }
        catch (UnsupportedJwtException exception)
        {
            logger.error("JWT Token is unsupported: {}", exception.getMessage());
        }
        catch (IllegalArgumentException exception)
        {
            logger.error("JWT claims string is empty: {}", exception.getMessage());
        }
        return false;


    }



}

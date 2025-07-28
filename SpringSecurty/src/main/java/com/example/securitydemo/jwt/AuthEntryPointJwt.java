package com.example.securitydemo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;


/*This code is present to be triggered in case request fails before authentication like
hitting a protected route with no JWT token

Instead of giving a blank page we return our custom code which we have set here

Now We simply implemented the inbuilt interface AuthenticationEntryPoint which had the commence method having request response and Auth
Exception
*/

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint
{
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException
    {
        logger.error("Unauthorized error:{}",authException.getMessage());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        final Map<String,Object>body=new HashMap<>();
        body.put("Status",HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error","Unauthorized");
        body.put("message",authException.getMessage());
        body.put("path",request.getServletPath());

        final ObjectMapper mapper=new ObjectMapper();
        mapper.writeValue(response.getOutputStream(),body);

    }
}

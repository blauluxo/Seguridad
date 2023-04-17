package com.example.pruebados.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.rmi.ServerException;
import java.util.Collections;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {


    @Override
    public Authentication attemptAuthentication(HttpServletRequest resquet,
                                                HttpServletResponse response) throws AuthenticationException {
        AuthCredentials authCredentials = new AuthCredentials();

    try{
        authCredentials = new ObjectMapper().readValue(resquet.getReader(), AuthCredentials.class);

    }catch (IOException a){
        System.out.println("Error en la clase JWTAUthentication");

    }
        UsernamePasswordAuthenticationToken usernameAPI =  new UsernamePasswordAuthenticationToken(
                authCredentials.getEmail(),
                authCredentials.getPassword(),
                Collections.emptyList()
                );

        return super.attemptAuthentication(resquet,response);

    }


    @Override
    protected void successfulAuthentication(HttpServletRequest resquet,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

       UserDetailsImpl userDetails = (UserDetailsImpl) authResult.getPrincipal();
        String token = TokenUtils.createToken(userDetails.getNombre(), userDetails.getUsername());


        response.addHeader("Authorization", "Bearer " +token);
        response.getWriter().flush();
        super.successfulAuthentication(resquet,response, chain,authResult );
    }

}

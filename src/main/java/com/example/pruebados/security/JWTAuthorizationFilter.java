package com.example.pruebados.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {
//poder cargar los datos o los permisos verificar antes para poder consultar los end points apis

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

    String bearertokens = request.getHeader("Authorization");

    if( bearertokens != null && bearertokens.startsWith("Bearer ")){
        String token = bearertokens.replace("Bearer ", "");
        UsernamePasswordAuthenticationToken usernamePAT = TokenUtils.getAuthetication(token);
        SecurityContextHolder.getContext().setAuthentication(usernamePAT);

        filterChain.doFilter(request, response);
    }

    }


}

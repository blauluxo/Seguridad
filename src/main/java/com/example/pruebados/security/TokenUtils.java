package com.example.pruebados.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

//ESTO ES LA CLASE TOKEN Y LO QUE PASA ESQUE AQUI SE CREA EL TOKEN Y EL USUARIO DE TOKEN.
public class TokenUtils {
    //CREAMOS LAS 2 VARIABLES EL TOKEN SECRETO Y EL TIEMPO DE EXPIRACION
    //ESTO ES EL TOKEN DE SEGURIDAD
    private final static String ACCESS_TOKEN_SECRET = "token1234";
    //SON 30 DIAS DE CADUCIDAD, 30 DIAS EN SEGUNDOS. 2 MILLONES
    private final static Long ACCESS_TOKEN_VALIDITY_SECONDS= 2_592_000l;

    //metodo para crear el token.


    public static String  createToken(String nombre, String email){

        long expirationTime = ACCESS_TOKEN_VALIDITY_SECONDS * 1000 ; //lo pasamos a milisegundos porque es lo que entiende java
        Date expirationDate = new Date(System.currentTimeMillis() + expirationTime);

        Map<String,Object> extra  = new HashMap<>();
        extra.put("nombre", nombre);

        return Jwts.builder()
                .setSubject(email)
                .setExpiration(expirationDate)
                .addClaims(extra) //lo añadimos
                .signWith(Keys.hmacShaKeyFor(ACCESS_TOKEN_SECRET.getBytes())) //con esto lo firmamos
                .compact(); //lo enviamos hacia el cliente
    }

    //esto es para crear un usuario a partir del token que le enviamos como parametro ok
    public static UsernamePasswordAuthenticationToken getAuthetication (String token){
     try{
         Claims claims = Jwts.parserBuilder()
                 .setSigningKey(ACCESS_TOKEN_SECRET.getBytes())
                 .build()
                 .parseClaimsJws(token)
                 .getBody();

         String email = claims.getSubject();

         return new UsernamePasswordAuthenticationToken(email, null, Collections.emptyList());
     }catch (JwtException e){
         System.out.println(e.getMessage());
         return  null;
     }
    }


}

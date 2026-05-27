package com.codesnippet.weather_service.util;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtil {
    private final long EXPIRE = 1000 * 60 * 60;

    private final String SECRET = "verysecureverysecureverysecure12";
    SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes());

    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRE))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

    }

    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJwt(token)
                .getBody();
    }

    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    private boolean isTokenExpired(String token) {
        return (extractClaims(token).getExpiration().before(new Date(System.currentTimeMillis())));
    }

    public boolean validateToken(String username, UserDetails userDetails, String token) {
        return (username.equals(userDetails.getUsername()) && isTokenExpired(token));
    }

}

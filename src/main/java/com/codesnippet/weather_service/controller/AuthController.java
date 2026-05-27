package com.codesnippet.weather_service.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.codesnippet.weather_service.entity.AuthRequest;
import com.codesnippet.weather_service.util.JWTUtil;

@RestController
public class AuthController {

    private AuthenticationManager authManager;
    private JWTUtil jwtUtil;

    @Autowired
    public AuthController(AuthenticationManager authManager, JWTUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/authenticate")
    public String generateToken(@RequestBody AuthRequest authRequest) {
        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
            return jwtUtil.generateToken(authRequest.getUsername());
        } catch (Exception e) {
            throw e;
        }

    }
}

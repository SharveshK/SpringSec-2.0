package com.sk.SpringSec.service;

import com.sk.SpringSec.model.Users;
import com.sk.SpringSec.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {

    @Autowired
    private JWTService jwtService;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    private UserRepo repo;


    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public Map<String, Object> register(Users user, String confirmPassword) {
        Map<String, Object> response = new HashMap<>();
        if (!user.getPassword().equals(confirmPassword)) {
            response.put("error", "Passwords do not match");
            return response;
        }
        if (user.getFirstName() == null || user.getFirstName().isEmpty()) {
            response.put("error", "First name is required");
            return response;
        }
        if (user.getLastName() == null || user.getLastName().isEmpty()) {
            response.put("error", "Last name is required");
            return response;
        }
        if (user.getPhoneNumber() == null || user.getPhoneNumber().isEmpty()) {
            response.put("error", "Phone number is required");
            return response;
        }
        if (!user.getPhoneNumber().matches("^\\+\\d{10,15}$")) {
            response.put("error", "Phone number must be in E.164 format (e.g., +1234567890)");
            return response;
        }
        if (repo.findByPhoneNumber(user.getPhoneNumber()) != null) {
            response.put("error", "Phone number already exists");
            return response;
        }
        if (user.getEmail() != null && !user.getEmail().isEmpty() && repo.findByEmail(user.getEmail()) != null) {
            response.put("error", "Email already exists");
            return response;
        }
        user.setUsername(user.getPhoneNumber());
        user.setPassword(encoder.encode(user.getPassword()));
        Users savedUser = repo.save(user);
        response.put("message", "User registered successfully");
        response.put("user", savedUser);
        return response;
    }

    public String verify(Users user) {
        Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(user.getUsername());
        } else {
            return "fail";
        }
    }
}

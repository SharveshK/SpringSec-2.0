package com.sk.SpringSec.controller;

import com.sk.SpringSec.model.Users;
import com.sk.SpringSec.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private UserService service;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, String> request) {
        Users user = new Users();
        try {
            user.setId(Integer.parseInt(request.get("id")));
        } catch (NumberFormatException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "Invalid ID format"));
        }
        user.setFirstName(request.get("firstName"));
        user.setLastName(request.get("lastName"));
        user.setPhoneNumber(request.get("phoneNumber"));
        user.setEmail(request.get("email"));
        user.setPassword(request.get("password"));
        String confirmPassword = request.get("confirmPassword");

        Map<String, Object> response = service.register(user, confirmPassword);
        if (response.containsKey("error")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public String login(@RequestBody Users user) {
        return service.verify(user);
    }
}
package com.example.board_spring4.user.controller;

import com.example.board_spring4.user.dto.UserRequestDto;
import com.example.board_spring4.user.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @ResponseBody
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody UserRequestDto userRequestDto){
        return userService.signUp(userRequestDto);
    }
    @ResponseBody
    @PostMapping("/login")
    public ResponseEntity<?> login (@RequestBody UserRequestDto userRequestDto, HttpServletResponse httpServletResponse){
        return userService.login(userRequestDto, httpServletResponse);
    }
}

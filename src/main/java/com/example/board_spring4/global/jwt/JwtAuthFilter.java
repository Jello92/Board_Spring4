package com.example.board_spring4.global.jwt;

import com.example.board_spring4.global.security.SecurityExceptionDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String token = jwtUtil.resolveToken(httpServletRequest);

        if(token != null) {
            if(!jwtUtil.validateToken(token)){
                jwtExceptionHandler(httpServletResponse, "Token Error", HttpStatus.UNAUTHORIZED.value());
                return;
            }
            Claims info = jwtUtil.getUserInfoFromToken(token);
            setAuthentication(info.getSubject());
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    public void setAuthentication(String username) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = jwtUtil.createAuthentication(username);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    public void jwtExceptionHandler(HttpServletResponse httpServletResponse, String msg, int statusCode) {
        httpServletResponse.setStatus(statusCode);
        httpServletResponse.setContentType("application/json");
        try {
            String json = new ObjectMapper().writeValueAsString(new SecurityExceptionDto(statusCode, msg));
            httpServletResponse.getWriter().write(json);
        } catch (Exception e) {
            log.error(e.getMessage());
        }
    }

}
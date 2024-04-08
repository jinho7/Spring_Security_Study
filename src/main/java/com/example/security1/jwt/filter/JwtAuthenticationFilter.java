package com.example.security1.jwt.filter;

import com.example.security1.dto.LoginRequestDto;
import com.example.security1.entity.User;
import com.example.security1.execption.ApiResponse;
import com.example.security1.jwt.dto.JwtDto;
import com.example.security1.jwt.userdetails.PrincipalDetails;
import com.example.security1.jwt.util.HttpResponseUtil;
import com.example.security1.jwt.util.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 라는게 있음
// /login 요청해서 username,password 전송하면 (POST)
// UsernamePasswordAuthenticationFilter 필터가 작동함

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    // /login 요청을 하면, 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        log.info("JwtAuthenticationFilter : 로그인 시도 중");

        // request에 있는 username과 password를 파싱해서 자바 Object로 받기
        ObjectMapper om = new ObjectMapper();
        LoginRequestDto loginRequestDto;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Error of request body.");
        }

        // 유저네임패스워드 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(
                        loginRequestDto.username(),
                        loginRequestDto.password());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행되고 정상이면 authentication이 return됨.
            // Token 넣어서 던져서 인증 끝나면 authentication을 주고, 로그인 한 정보가 담긴다.
            // DB에 있는 username과 password가 일치한다는 뜻
            return authenticationManager.authenticate(authenticationToken);
        // authenticate() 메서드가 호출된 직후에 해당되는데, 실제 비밀번호는 AuthenticationManager의 구현체인 ProviderManager에서 password는 제거됨.
    }


    // JWT Token 생성해서 response에 담아주기
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException{

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        log.info("[*] Login Success! - Login with " + principalDetails.getUsername());
        JwtDto jwtDto = new JwtDto(
                jwtUtil.createJwtAccessToken(principalDetails),
                jwtUtil.createJwtRefreshToken(principalDetails)
        );

        log.info("Access Token: " + jwtDto.accessToken());
        log.info("Refresh Token: " + jwtDto.refreshToken());

        HttpResponseUtil.setSuccessResponse(response, HttpStatus.CREATED, jwtDto);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException {

        // 실패한 인증에 따라 적절한 오류 메시지 설정
        String errorMessage;
        if (failed instanceof BadCredentialsException) {
            errorMessage = "Bad credentials";
        } else if (failed instanceof LockedException) {
            errorMessage = "Account is locked";
        } else if (failed instanceof DisabledException) {
            errorMessage = "Account is disabled";
        } else if (failed instanceof UsernameNotFoundException) {
            errorMessage = "Account not found";
        } else if (failed instanceof AuthenticationServiceException) {
            errorMessage = "Error occurred while parsing request body";
        } else {
            errorMessage = "Authentication failed";
        }
        log.info("[*] Login Fail - " + errorMessage);

        HttpResponseUtil.setErrorResponse(response, HttpStatus.UNAUTHORIZED, errorMessage);

    }

}
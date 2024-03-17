package com.example.security1.jwt.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class JwtDto {
    private final String accessToken;
    private final String refreshToken;
}
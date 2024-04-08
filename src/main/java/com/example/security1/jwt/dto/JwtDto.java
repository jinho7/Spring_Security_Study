package com.example.security1.jwt.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

public record JwtDto(
        String accessToken,
        String refreshToken
) {
}
package com.example.security1.dto;

import lombok.Data;

public record LoginRequestDto(
        String username,
        String password
) {
}

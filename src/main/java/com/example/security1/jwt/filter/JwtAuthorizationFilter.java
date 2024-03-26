package com.example.security1.jwt.filter;

import com.example.security1.jwt.userdetails.PrincipalDetails;
import com.example.security1.jwt.util.JwtUtil;
import com.example.security1.jwt.util.RedisUtil;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        log.info("[*] Jwt Filter");

        try {
            String accessToken = jwtUtil.resolveAccessToken(request);

            // accessToken 없이 접근할 경우
            if (accessToken == null) {
                filterChain.doFilter(request, response);
                return;
            }

            // logout 처리된 accessToken
            if (redisUtil.get(accessToken) != null && redisUtil.get(accessToken).equals("logout")) {
                logger.info("[*] Logout accessToken");
                filterChain.doFilter(request, response);
                return;
            }

            log.info("[*] Authorization with Token");
            authenticateAccessToken(accessToken);

            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            log.warn("[*] case : accessToken Expired");
        }
    }

    private void authenticateAccessToken(String accessToken) {
        jwtUtil.validateToken(accessToken);

        PrincipalDetails principalDetails = new PrincipalDetails(
                jwtUtil.getUsername(accessToken),
                null,
                jwtUtil.getRoles(accessToken)
        );

        log.info("[*] Authority Registration");

        // 현재 우리는 Token 서명으로 무결성을 검증하였기 때문에 username을 가지고 강제로 Authentication 을 만들어
        // securityContextHolder에 넣어주면 된다.
        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(
                principalDetails,
                null,
                principalDetails.getAuthorities());

        // 컨텍스트 홀더에 저장
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }
}
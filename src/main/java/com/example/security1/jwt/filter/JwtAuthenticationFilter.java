package com.example.security1.jwt.filter;

import com.example.security1.dto.LoginRequestDto;
import com.example.security1.entity.User;
import com.example.security1.jwt.userdetails.PrincipalDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 라는게 있음
// /login 요청해서 username,password 전송하면 (POST)
// UsernamePasswordAuthenticationFilter 필터가 작동함

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면, 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

        // 1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            // Token 넣어서 던져서 인증 끝나면 authentication을 주고, 로그인 한 정보가 담긴다.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session에 저장. -> 로그인이 되었다는 이야기
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(principalDetails.getUser().getUsername());

            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }



//
//        // request에 있는 username과 password를 파싱해서 자바 Object로 받기
//        ObjectMapper om = new ObjectMapper();
//        LoginRequestDto loginRequestDto = null;
//        try {
//            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDto.class);
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        System.out.println("JwtAuthenticationFilter : "+loginRequestDto);
//
//        // 유저네임패스워드 토큰 생성
//        UsernamePasswordAuthenticationToken authenticationToken =
//                new UsernamePasswordAuthenticationToken(
//                        loginRequestDto.getUsername(),
//                        loginRequestDto.getPassword());
//
//        System.out.println("JwtAuthenticationFilter : 토큰생성완료");
//
//        // authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
//        // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
//        // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
//        // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
//        // Authentication 객체를 만들어서 필터체인으로 리턴해준다.
//
//        // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
//        // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
//        // 결론은 인증 프로바이더에게 알려줄 필요가 없음.
//        Authentication authentication =
//                authenticationManager.authenticate(authenticationToken);
//
//        PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
//        System.out.println("Authentication : " + principalDetailis.getUser().getUsername()); // 로그인이 정상적으로 되었다.
//
//        // authenticaition 객체가 session 영역에 저장 해야하고, 그 방법 - return 해주면 저장됨.
//        // Return의 이유는 경로별 권한 관리를 security 가 대신 해주기 때문에 편하려고 하는거
//        // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유는 없음.
//        return authentication;

    }


    // JWT Token 생성해서 response에 담아주기
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {

        PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();

//        // 리프레시 토큰, 엑세스 토큰으로 나눠서 제작
//        String jwtToken = JWT.create()
//                .withSubject(principalDetailis.getUsername())
//                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))
//                .withClaim("id", principalDetailis.getUser().getId())
//                .withClaim("username", principalDetailis.getUser().getUsername())
//                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
//
//        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);
    }

}
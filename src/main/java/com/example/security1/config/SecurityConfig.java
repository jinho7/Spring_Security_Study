package com.example.security1.config;

import com.example.security1.jwt.filter.JwtAuthenticationFilter;
import com.example.security1.jwt.filter.JwtAuthorizationFilter;
import com.example.security1.jwt.filter.JwtLogoutFilter;
import com.example.security1.jwt.util.HttpResponseUtil;
import com.example.security1.jwt.util.JwtUtil;
import com.example.security1.jwt.util.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // cors 비활성화
        http.
                cors(cors -> cors
                .configurationSource(CorsConfig.apiConfigurationSource()));
        // csrf 비활성화
        http.
                csrf().disable();
        // fromLogin 비활성화
        http
                .formLogin().disable();
        // httpBasic 인증방식 비활성화
        http
                .httpBasic().disable();

        // Session을 사용하지 않고, Stateless 서버를 만듬.
        http.
                 sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // 경로별 인가
        http.
                authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/user/**","/reissue").authenticated()
                                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                                .anyRequest().permitAll()
                )
                .formLogin(withDefaults());

        // JWT login
        // Jwt Filter (with login)
        JwtAuthenticationFilter loginFilter = new JwtAuthenticationFilter(
                authenticationManager(authenticationConfiguration), jwtUtil);
        loginFilter.setFilterProcessesUrl("/login");

        http
                .addFilterAt(loginFilter, UsernamePasswordAuthenticationFilter.class);
        http
                .addFilterBefore(new JwtAuthorizationFilter(jwtUtil, redisUtil), JwtAuthenticationFilter.class);


        // Logout Filter
        http
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(new JwtLogoutFilter(redisUtil, jwtUtil))
                        .logoutSuccessHandler((request, response, authentication) ->
                                HttpResponseUtil.setSuccessResponse(
                                        response,
                                        HttpStatus.OK,
                                        "로그아웃 성공"
                                )
                        )
                );

        return http.build();
    }
}
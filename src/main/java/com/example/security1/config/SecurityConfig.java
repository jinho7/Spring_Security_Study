package com.example.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration // IoC 빈(bean)을 등록
@EnableWebSecurity // 필터 체인 관리 시작 어노테이션
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true) // 특정 주소 접근시 권한 및 인증을 위한 어노테이션 활성화
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // cors 사용 X 모든 요청 허용 **
        // @CrossOrigin과의 차이점 : @CrossOrigin은 인증이 없을 때 문제, 그래서 직접 시큐리티 필터에 등록!
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

        http.
                authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .antMatchers("/user/**").authenticated()
                                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                                .anyRequest().permitAll()
                )
                .formLogin(withDefaults());
        return http.build();
    }
}
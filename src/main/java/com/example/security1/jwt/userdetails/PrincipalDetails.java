package com.example.security1.jwt.userdetails;

// Security가 /login 주소 요청이 오면, 낚아채서 로그인 진행
// 로그인 완료 후 Security Session을 만들어준다! ("Security ContextHolder"에 Session을 저장.)
// 오브젝트 -> Authentication 타입의 객체
// Authentication 안에 User 정보가 있어야 한다.
// User 오브젝트 타입 -> UserDetails 타입의 객체

// Security Session -> Authentication -> User Detatils (Principal Details)

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class PrincipalDetails implements UserDetails {

    private final String username;
    private final String password;
    private final String roles;

    public PrincipalDetails(String username, String password, String roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }

    // 해당 User의 권한을 리턴 하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(roles));

        return authorities;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // 사이트에서 1년 동안 회원이 로그인을 안하면 -> 휴면 계정으로 전환하는 로직이 있다고 치자
        // user entity의 field에 "Timestamp loginDate"를 하나 만들어주고
        // (현재 시간 - loginDate) > 1년 -> return false; 로 설정
        return true;
    }
}

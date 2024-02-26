package com.example.security1.config.auth;

import com.example.security1.entity.User;
import com.example.security1.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.sql.SQLOutput;
import java.util.Optional;

// 시큐리티 설정에서 loginProcessingUrl("/login"); 걸어놓음
// login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어 있는 loadUserByUsername 함수가 실행된다.
@Service
public class PrincipalDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("username : "+ username);
        Optional<User> userEntity = userRepository.findByUsername(username);
        if (userEntity.isPresent()) {
            return new PrincipalDetails(userEntity.get());
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }
}
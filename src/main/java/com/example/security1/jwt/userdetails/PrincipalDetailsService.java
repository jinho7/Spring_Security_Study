package com.example.security1.jwt.userdetails;

import com.example.security1.entity.User;
import com.example.security1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

// formLogin 꺼놔서, http://localhost:8080/login 요청이 올 때 이 PrincipalDetailsService가 동작한다!
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    @Autowired
    public PrincipalDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<User> userEntity = userRepository.findByUsername(username);
        if (userEntity.isPresent()) {
            return new PrincipalDetails(userEntity.get());
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }
}
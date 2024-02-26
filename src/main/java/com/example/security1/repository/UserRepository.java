package com.example.security1.repository;

import com.example.security1.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// 기본적인 CRUD 함수 제공 (in JpaRepository)
public interface UserRepository extends JpaRepository<User, Integer> {

    // Jpa Naming 전략
    Optional<User> findByUsername(String username);

}

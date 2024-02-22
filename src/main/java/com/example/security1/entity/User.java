package com.example.security1.entity;

import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import javax.persistence.*;
import java.sql.Timestamp;

@Data
@Entity
public class User {
    @Id // primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String username;
    private String password;
    private String email;
    private String role; //ROLE_USER, ROLE_ADMIN
    @CreationTimestamp
    private Timestamp createDate;
}
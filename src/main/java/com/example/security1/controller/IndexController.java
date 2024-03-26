package com.example.security1.controller;

import com.example.security1.entity.User;
import com.example.security1.execption.ApiResponse;
import com.example.security1.jwt.dto.JwtDto;
import com.example.security1.jwt.util.JwtUtil;
import com.example.security1.repository.UserRepository;
import com.example.security1.service.UserService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RequiredArgsConstructor
@RestController // view를 리턴하겠다
public class IndexController {

	private UserService userService;

	private final JwtUtil jwtUtil;

	// localhost:8080
	@GetMapping({"/"})
	public String index() {
		// 머스테치 기본폴더 src/main/resources/templates/
		// view resolver 설정: templates (prefix), .mustache (suffix) 생략가능
		return "index"; // src/main/resources/templates/index.mustache
	}

	@GetMapping("/user")
	public @ResponseBody String user() {
		return "user";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "admin";
	}

	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "manager";
	}

	@GetMapping("/login")
	public String login() {
		return "loginForm";
	}

	@GetMapping("/join")
	public String join() {
		return "joinForm";
	}

	@PostMapping("/join")
	public String join(@RequestBody User user) {
		userService.register(user);
		return "redirect:/loginForm";
	}
	@GetMapping("/reissue")
	public ApiResponse<JwtDto> reissueToken(@RequestHeader("RefreshToken") String refreshToken) {
		return ApiResponse.onSuccess(jwtUtil.reissueToken(refreshToken));
	}

}
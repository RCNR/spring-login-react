package org.example.backend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 암호화 진행하는 메서드
    // 비밀번호는 BCrypt로 단방향 암호화 Bean
    @Bean
    public PasswordEncoder passwordEncoder() { // 인터페이스 타입으로 리턴
        return new BCryptPasswordEncoder(); // 구현체 리턴
    }
}

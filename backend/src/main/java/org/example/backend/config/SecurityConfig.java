package org.example.backend.config;

import jakarta.servlet.http.HttpServletResponse;
import org.example.backend.filter.LoginFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final AuthenticationSuccessHandler socialSuccessHandler;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration,
                          @Qualifier("LoginSuccessHandler") AuthenticationSuccessHandler loginSuccessHandler,
                          @Qualifier("SocialSuccessHandler") AuthenticationSuccessHandler socialSuccessHandler) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.socialSuccessHandler = socialSuccessHandler;
    }


    // 암호화 진행하는 메서드
    // 비밀번호는 BCrypt로 단방향 암호화 Bean
    @Bean
    public PasswordEncoder passwordEncoder() { // 인터페이스 타입으로 리턴
        return new BCryptPasswordEncoder(); // 구현체 리턴
    }

    // 커스텀 로그인 필터를 위한 AuthenticationManager 빈 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }


    // securityFilterChain 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // stateless 하기에 csrf 비활성화
        http.csrf(AbstractHttpConfigurer::disable);

        // CORS 설정

        // 기본 form 기반 로그인 비활성화 -> Login Filter 직접 작성 필요
        http.formLogin(AbstractHttpConfigurer::disable);

        // 기본 basic 인증 필터 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // OAuth2 인증용
        http
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(socialSuccessHandler));

        // 인가
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        //  커스터 필터 (LoginFilter) 추가
        /**
         * 여기서 UsernamePasswordAuthenticationFilter.class 는
         * 기준이 되는 필터이다.
         * LoginFilter는 생성자로부터 AUthenticationManager(인증 진행 인터페이스)를 주입 받는다.
         * 따라서 직접 넣어야 한다.
         */
        http.addFilterBefore(new LoginFilter(authenticationManager(authenticationConfiguration), loginSuccessHandler), UsernamePasswordAuthenticationFilter.class);

        // 예외 처리
        http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED); // 로그인 X
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN); // 권한 X
                        })
                );

        // 세션 필터 설정 - stateless 설정
        http.sessionManagement(session -> session.
                sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}

package com.jwt.authentication.springboot.security;

import com.jwt.authentication.springboot.services.DetalheUsuarioServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

public class JWTConfiguracao extends WebSecurityConfiguration {

    private final DetalheUsuarioServiceImpl detalheUsuarioService;
    private final PasswordEncoder passwordEncoder;

    public JWTConfiguracao(DetalheUsuarioServiceImpl detalheUsuarioService, PasswordEncoder passwordEncoder) {
        this.detalheUsuarioService = detalheUsuarioService;
        this.passwordEncoder = passwordEncoder;
    }

    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(detalheUsuarioService).passwordEncoder(passwordEncoder);
    }
    protected  void  configure(HttpSecurity http) throws Exception{
        http.csrf().disable().authorizeHttpRequests().anyRequest()
                .authenticated().and()
                .addFilter(new JWTAutenticarFilter())
                .addFilter(new JWTValidarFilter())
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(){
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
        source.registerCorsConfiguration("/**",corsConfiguration);
        return source;
    }
}

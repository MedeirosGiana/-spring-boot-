package com.jwt.authentication.springboot.repository;

import com.jwt.authentication.springboot.model.UsuarioModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<UsuarioModel,Integer> {
    public Optional<UsuarioModel> findByLogin(String login);
}

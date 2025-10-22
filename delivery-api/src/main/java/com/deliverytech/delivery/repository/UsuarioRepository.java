package com.deliverytech.delivery.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

import com.deliverytech.delivery.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByEmail(String email);

    Optional<Usuario> findByUsername(String username);
}

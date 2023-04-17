package com.example.pruebados.repositorio;

import com.example.pruebados.modelo.Paciente;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@EnableJpaRepositories(basePackages = "com.example.pruebados.modelo")

public interface PacienteRepositorio extends JpaRepository<Paciente, Integer> {
    List<Paciente> findAll();
    @Override
    Optional<Paciente> findById(Integer id);
    Optional<Paciente> findOneByEmail(String email);

}

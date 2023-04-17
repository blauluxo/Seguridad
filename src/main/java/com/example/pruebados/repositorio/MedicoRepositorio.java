package com.example.pruebados.repositorio;

import com.example.pruebados.modelo.Medico;
import com.example.pruebados.modelo.Paciente;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@EnableJpaRepositories(basePackages = "com.example.pruebados.modelo")

public interface MedicoRepositorio extends JpaRepository<Medico, Integer> {

List<Medico> findAll();
    //te devuelve el id del medico
    @Override
    Optional<Medico> findById(Integer id);
}

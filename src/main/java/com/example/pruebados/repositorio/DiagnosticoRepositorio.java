package com.example.pruebados.repositorio;


import com.example.pruebados.modelo.Diagnostico;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DiagnosticoRepositorio extends JpaRepository<Diagnostico, Integer>{

    List<Diagnostico> findAll();
}

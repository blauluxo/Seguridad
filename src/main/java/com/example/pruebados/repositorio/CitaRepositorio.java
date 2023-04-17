package com.example.pruebados.repositorio;

import com.example.pruebados.modelo.Cita;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CitaRepositorio extends JpaRepository<Cita, Integer> {

    //te devuelve una lista de citas
    List<Cita> findAll();

}

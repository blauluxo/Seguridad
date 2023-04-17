package com.example.pruebados.repositorio;

import com.example.pruebados.modelo.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@EnableJpaRepositories(basePackages = "com.example.pruebados.modelo")
public interface UsuarioRepositorio extends JpaRepository<Usuario, Integer> {

List<Usuario> findByNombreContaining(String nombre); //lista que te devuelve los nombres
Usuario findByNombre(String nombre); //te devuelve el usuario

List<Usuario> findAll();  //lista que te devuelve todos



}

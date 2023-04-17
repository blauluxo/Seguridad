package com.example.pruebados.Dtos.dto;

import com.example.pruebados.modelo.Medico;

import java.util.ArrayList;
import java.util.List;

public class PacienteDto {

    //variables
    private   int id;
    private  String nombre;
    private  String apellidos;
    private   String usuario;
    private   String telefono;
    private   List<Medico> medicos ;
    //contructores

    public PacienteDto(int id, String nombre, String apellidos, String usuario, String telefono, List<Medico> medicos) {
        this.id = id;
        this.nombre = nombre;
        this.apellidos = apellidos;
        this.usuario = usuario;
        this.telefono = telefono;
        this.medicos = medicos;
    }

    public PacienteDto(){

    }

    //metodos


    public List<Medico> getMedicos() {
        return medicos;
    }

    public void setMedicos(List<Medico> medicos) {
        this.medicos = medicos;
    }

    public String getTelefono() {
        return telefono;
    }

    public void setTelefono(String telefono) {
        this.telefono = telefono;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getApellidos() {
        return apellidos;
    }

    public void setApellidos(String apellidos) {
        this.apellidos = apellidos;
    }

    public String getUsuario() {
        return usuario;
    }

    public void setUsuario(String usuario) {
        this.usuario = usuario;
    }
}

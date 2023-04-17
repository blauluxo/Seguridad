package com.example.pruebados.Dtos.dto;

public class MedicoDto {

    private   int id;
    private  String nombre;
    private  String apellidos;
    private   String usuario;
    private String numcolegiado;


    public MedicoDto(int id, String nombre, String apellidos, String usuario, String numcolegiado) {
        this.id = id;
        this.nombre = nombre;
        this.apellidos = apellidos;
        this.usuario = usuario;
        this.numcolegiado = numcolegiado;
    }

    public MedicoDto() {
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

    public String getNumcolegiado() {
        return numcolegiado;
    }

    public void setNumcolegiado(String numcolegiado) {
        this.numcolegiado = numcolegiado;
    }
}

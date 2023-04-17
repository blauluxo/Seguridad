package com.example.pruebados.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table (name="Paciente")
public class Paciente extends Usuario {

    //@PrimaryKeyJoinColumn(name = "ID")

    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "pacienteSeq")
    @SequenceGenerator(name = "pacienteSeq", sequenceName = "pacienteSeq", allocationSize = 1)
    @Basic
    @Column(name = "PACIENTE_ID", unique = true)
    private Integer pacienteId;
    @Basic
    @Column(name = "NSS")
    private String nss;
    @Basic
    @Column(name = "NUMTARJETA")
    private String numtarjeta;
    @Basic
    @Column(name = "TELEFONO")
    private String telefono;
    @Basic
    @Column(name = "DIRECCION")
    private String direccion;


//------------esto es para la relacion 1 a muchos de entre paciente y medico----------

    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(
            name = "medicoPaciente",
            joinColumns = @JoinColumn(name = "PACIENTE_ID"),
            inverseJoinColumns = @JoinColumn(name = "MEDICO_ID")
    )
    private List<Medico> medicos = new ArrayList<>();

    public void getMedicos(Medico medico) {
         medicos.add(medico);
    }

    public String getNss() {
        return nss;
    }

    public void setNss(String nss) {
        this.nss = nss;
    }

    public String getNumtarjeta() {
        return numtarjeta;
    }

    public void setNumtarjeta(String numtarjeta) {
        this.numtarjeta = numtarjeta;
    }

    public String getTelefono() {
        return telefono;
    }

    public void setTelefono(String telefono) {
        this.telefono = telefono;
    }

    public String getDireccion() {
        return direccion;
    }

    public void setDireccion(String direccion) {
        this.direccion = direccion;
    }






}

package com.example.pruebados.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Entity
@Table(name="Medico")
public class Medico extends Usuario {

    //@PrimaryKeyJoinColumn(name = "ID")

    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "medicoSeq")
    @SequenceGenerator(name = "medicoSeq", sequenceName = "medicoSeq", allocationSize = 1)
    @Basic
    @Column(name = "MEDICO_ID",  unique = true)
    private Integer medicoId;
    @Basic
    @Column(name = "NUMCOLEGIADO")
    private String numcolegiado;


    //------------esto es para la relacion 1 a muchos de entre paciente y

    @ManyToMany(mappedBy = "medicos", cascade = CascadeType.ALL)
    List<Paciente> listaPaciente;
    public List<Paciente> getPaciente() {
        return listaPaciente;
    }
    public void setPaciente(List<Paciente> paciente) {
        this.listaPaciente = paciente;
    }
    //añadimos un paciente ala lista de medicos y un paciente al medico.
    public void añadirPaciente(Paciente paciente, Medico medico) {
        listaPaciente.add(paciente);
        paciente.getMedicos(medico); // Agregar este medico a la lista de medicos del paciente
    }

    public String getNumcolegiado() {
        return numcolegiado;
    }

    public void setNumcolegiado(String numcolegiado) {
        this.numcolegiado = numcolegiado;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Medico medico = (Medico) o;

   //     if (usuarioId != null ? !usuarioId.equals(medico.usuarioId) : medico.usuarioId != null) return false;
        if (numcolegiado != null ? !numcolegiado.equals(medico.numcolegiado) : medico.numcolegiado != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = 0;
        result = 31 * result + (numcolegiado != null ? numcolegiado.hashCode() : 0);
        return result;
    }


}

package com.example.pruebados.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigInteger;

@Entity
@Table(name="Diagnostico")
@Data
@AllArgsConstructor
@NoArgsConstructor

public class Diagnostico {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "ID_DIAGNOSTICO")
    private Integer idDiagnostico;
    @Basic
    @Column(name = "VALORACIONESPECIALISTA")
    private String valoracionespecialista;
    @Basic
    @Column(name = "ENFERMEDAD")
    private String enfermedad;

    @Basic
    @Column(name = "CITA_ID")
    private String citaId;


    @OneToOne
    @JoinColumn(name = "CITA_ID", referencedColumnName = "ID_CITA",insertable=false, updatable=false)
    private Cita citaByCitaId;


}

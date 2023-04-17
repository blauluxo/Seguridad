package com.example.pruebados.modelo;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.sql.Date;

@Entity
@Data
@Table(name="Cita")
@AllArgsConstructor
@NoArgsConstructor


public class Cita {

//columna id
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    @Column(name = "ID_CITA")
    private Integer idCita;

//columnas basicas
    @Basic
    @Column(name = "FECHAHORA")
    private Date fechahora;
    @Basic
    @Column(name = "MOTIVOCITA")
    private String motivocita;
    @Basic
    @Column(name = "ATRIBUTO11")
    private Integer atributo11;
    @Basic
    @Column(name = "citaUsuarioId")
    private Integer citaUsuarioId;

//--relacion con usuario
    @ManyToOne
    @JoinColumn(name = "citaUsuarioId",referencedColumnName = "ID", insertable = false, updatable = false)
    private Usuario usuario;

//--metodos
    public Integer getIdCita() {
        return idCita;
    }

    public void setIdCita(Integer idCita) {
        this.idCita = idCita;
    }

    public Date getFechahora() {
        return fechahora;
    }

    public void setFechahora(Date fechahora) {
        this.fechahora = fechahora;
    }

    public String getMotivocita() {
        return motivocita;
    }

    public void setMotivocita(String motivocita) {
        this.motivocita = motivocita;
    }

    public Integer getAtributo11() {
        return atributo11;
    }

    public void setAtributo11(Integer atributo11) {
        this.atributo11 = atributo11;


    }
}

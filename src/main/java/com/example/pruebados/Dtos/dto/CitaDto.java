package com.example.pruebados.Dtos.dto;

import java.sql.Date;

public class CitaDto {

    private Integer idCita;
    private Date fechahora;
    private String motivocita;
    private Integer citaUsuarioId;

    public CitaDto(Integer idCita, Date fechahora, String motivocita, Integer citaUsuarioId) {
        this.idCita = idCita;
        this.fechahora = fechahora;
        this.motivocita = motivocita;
        this.citaUsuarioId = citaUsuarioId;
    }

    public CitaDto() {
    }

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

    public Integer getCitaUsuarioId() {
        return citaUsuarioId;
    }

    public void setCitaUsuarioId(Integer citaUsuarioId) {
        this.citaUsuarioId = citaUsuarioId;
    }
}

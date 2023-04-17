package com.example.pruebados.Dtos.dto;

public class DiagnosticoDto {


    private Integer idDiagnostico;
    private String valoracionespecialista;
    private String enfermedad;
    private String citaId;


    public DiagnosticoDto(Integer idDiagnostico, String valoracionespecialista, String enfermedad, String citaId) {
        this.idDiagnostico = idDiagnostico;
        this.valoracionespecialista = valoracionespecialista;
        this.enfermedad = enfermedad;
        this.citaId = citaId;
    }

    public DiagnosticoDto() {
    }

    public Integer getIdDiagnostico() {
        return idDiagnostico;
    }

    public void setIdDiagnostico(Integer idDiagnostico) {
        this.idDiagnostico = idDiagnostico;
    }

    public String getValoracionespecialista() {
        return valoracionespecialista;
    }

    public void setValoracionespecialista(String valoracionespecialista) {
        this.valoracionespecialista = valoracionespecialista;
    }

    public String getEnfermedad() {
        return enfermedad;
    }

    public void setEnfermedad(String enfermedad) {
        this.enfermedad = enfermedad;
    }

    public String getCitaId() {
        return citaId;
    }

    public void setCitaId(String citaId) {
        this.citaId = citaId;
    }
}

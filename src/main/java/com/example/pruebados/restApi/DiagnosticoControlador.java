package com.example.pruebados.restApi;

import com.example.pruebados.Dtos.dto.DiagnosticoDto;
import com.example.pruebados.modelo.Diagnostico;
import com.example.pruebados.service.DiagnosticoServicio;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/diagnostico")
public class DiagnosticoControlador {

    private final DiagnosticoServicio diagnosticoServicio;


    public DiagnosticoControlador(DiagnosticoServicio diagnosticoServicio) {
        this.diagnosticoServicio = diagnosticoServicio;
    }

    @PostMapping
    public Diagnostico crearCita(@RequestBody Diagnostico diagnostico){
        return diagnosticoServicio.crearDiagnostico(diagnostico);
    }

    @GetMapping("/lista")
    public List<Diagnostico> getTodosPacientes(){
        return diagnosticoServicio.getTodosDiagnosticos();
    }

    @GetMapping("/dtos")
    public List<DiagnosticoDto> getTodasCitasDtos(){
        return diagnosticoServicio.getTodosDiagnosticosDtos();
    }

}

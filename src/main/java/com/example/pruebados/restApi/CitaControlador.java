package com.example.pruebados.restApi;

import com.example.pruebados.Dtos.dto.CitaDto;
import com.example.pruebados.modelo.Cita;
import com.example.pruebados.service.CitaServicio;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/citas")
public class CitaControlador {
//DTOs MAPS STRUTS  //IMPLEMENTA SERIALIZABLE
   private final CitaServicio citaServicio;

    public CitaControlador(CitaServicio citaServicio) {
        this.citaServicio = citaServicio;
    }

    @PostMapping
    public Cita crearCita(@RequestBody Cita cita){
        return citaServicio.crearCita(cita);
    }

    @GetMapping("/lista")
    public List<Cita> getTodasCitas(){
        return citaServicio.getTodasCitas();
    }


    //--------------------------parte de los DTOS-----------------------------
    @GetMapping("/dtos")
    public List<CitaDto> getTodasCitasDtos(){
        return citaServicio.getTodasCitasDtos();
    }


}

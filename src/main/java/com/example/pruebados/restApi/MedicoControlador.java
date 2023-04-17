package com.example.pruebados.restApi;

import com.example.pruebados.Dtos.dto.MedicoDto;
import com.example.pruebados.modelo.Medico;
import com.example.pruebados.service.MedicoServicio;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/medicos")
public class MedicoControlador {

    private final MedicoServicio medicoServicio;


    public MedicoControlador(MedicoServicio medicoServicio) {
        this.medicoServicio = medicoServicio;
    }


    @PostMapping
    public Medico crearPaciente(@RequestBody Medico medico){
        return medicoServicio.crearMedico(medico);
    }

    @GetMapping("/lista")
    public List<Medico> getTodosPacientes(){
        return medicoServicio.getTodosMedicos();
    }

    //te retorna el medico por ese id
    @GetMapping("/{id}")
    public Optional<Medico> getMedicoById(@PathVariable int id){
        return medicoServicio.getMedicoById(id);
    }

    //--------------------------parte de los DTOS-----------------------------
    @GetMapping("/dtos")
    public List<MedicoDto> getTodosMedicosDtos(){
        return medicoServicio.getTodosLosMedicosDtos();
    }
}

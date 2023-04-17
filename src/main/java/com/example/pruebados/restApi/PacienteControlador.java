package com.example.pruebados.restApi;

import com.example.pruebados.Dtos.dto.PacienteDto;
import com.example.pruebados.modelo.Paciente;
import com.example.pruebados.service.PacienteServicio;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/pacientes")
public class PacienteControlador {

    private final PacienteServicio pacienteServicio;
    //esto es el cosntructor
    public PacienteControlador(PacienteServicio pacienteServicio) {
        this.pacienteServicio = pacienteServicio;
    }


    @PostMapping
    public Paciente crearPaciente(@RequestBody Paciente paciente){
        return pacienteServicio.crearPaciente(paciente);
    }
    //te da la lista
    @GetMapping("/lista")
    public List<Paciente> getTodosPacientes(){
        return pacienteServicio.getTodosPaciente();
    }
    //te devuelve los id
    @GetMapping("/{id}")
    public Optional<Paciente> getPacienteById(@PathVariable int id){
        return pacienteServicio.getPacienteById(id);}


    //--------------------------parte de los DTOS-----------------------------
    @GetMapping("/dtos")
    public List<PacienteDto> getTodosLosDtos(){
        return pacienteServicio.getTodosPacienteDtos();
    }

}

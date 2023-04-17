package com.example.pruebados.service;

import com.example.pruebados.Dtos.dto.PacienteDto;
import com.example.pruebados.Dtos.interfazDto.InterfazPacienteDto;
import com.example.pruebados.modelo.Paciente;
import com.example.pruebados.repositorio.PacienteRepositorio;
import org.mapstruct.factory.Mappers;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class PacienteServicio {


    private final PacienteRepositorio pacienteRepositorio;

// es el constructor
    public PacienteServicio(PacienteRepositorio pacienteRepositorio) {
        this.pacienteRepositorio = pacienteRepositorio;
    }

   //aqui los metodos
   public Paciente crearPaciente(Paciente paciente){
        return pacienteRepositorio.save(paciente);
   }

   public List<Paciente> getTodosPaciente(){
        return pacienteRepositorio.findAll();
   }

   public Optional<Paciente> getPacienteById(Integer id){
        return pacienteRepositorio.findById(id);}

//-------------------------------------------------PARTE DEL DTO-----------------------------------------------

    //---mapeo autoamitoco
    public List<PacienteDto> getTodosPacienteDtos(){

        //creo dos listas una de pacientes y otra de DTos
        List<Paciente> listaPaciente = pacienteRepositorio.findAll();
        List<PacienteDto> listaPacienteDto = new ArrayList<>();

        //creo un modeloMapper y luego le digo que la estrategia es stricta,
        // para que solamente copie los elementos que se llaman igual
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);

        //añadimos a la lista pacienteDto los datos de la lista Paciente
        for(Paciente pacientes: listaPaciente ){
            listaPacienteDto.add(modelMapper.map(pacientes, PacienteDto.class));
        }

        return listaPacienteDto;
    }
    //mapeo manual
    private PacienteDto getPacienteToDTO(Paciente paciente) {
        PacienteDto pacienteDTO = new PacienteDto();
        pacienteDTO.setNombre(paciente.getNombre());
        pacienteDTO.setApellidos(paciente.getApellidos());
        // Mapear otros campos
        return pacienteDTO;
    }
//-----------------------------------



}
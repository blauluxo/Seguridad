package com.example.pruebados.service;

import com.example.pruebados.Dtos.dto.CitaDto;
import com.example.pruebados.modelo.Cita;
import com.example.pruebados.repositorio.CitaRepositorio;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CitaServicio {

    private final CitaRepositorio citaRepositorio;

    public CitaServicio(CitaRepositorio citaRepositorio) {
        this.citaRepositorio = citaRepositorio;
    }

    public Cita crearCita (Cita cita){
        return citaRepositorio.save(cita);
    }

    public List<Cita> getTodasCitas(){
        return citaRepositorio.findAll();
    }


    //---mapeo autoamitoco
    public List<CitaDto> getTodasCitasDtos(){

        //creo dos listas una de pacientes y otra de DTos
        List<Cita> listaCitas = citaRepositorio.findAll();
        List<CitaDto> listaCitasDtos = new ArrayList<>();

        //creo un modeloMapper y luego le digo que la estrategia es stricta,
        // para que solamente copie los elementos que se llaman igual
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);

        //añadimos a la lista pacienteDto los datos de la lista Paciente
        for(Cita citas: listaCitas ){
            listaCitasDtos.add(modelMapper.map(citas, CitaDto.class));
        }

        return listaCitasDtos;
    }
}

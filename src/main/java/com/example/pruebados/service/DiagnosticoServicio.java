package com.example.pruebados.service;

import com.example.pruebados.Dtos.dto.DiagnosticoDto;
import com.example.pruebados.modelo.Diagnostico;
import com.example.pruebados.repositorio.DiagnosticoRepositorio;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DiagnosticoServicio {

    private final DiagnosticoRepositorio diagnosticoRepositorio;

    public DiagnosticoServicio(DiagnosticoRepositorio diagnosticoRepositorio) {
        this.diagnosticoRepositorio = diagnosticoRepositorio;
    }

    public Diagnostico crearDiagnostico (Diagnostico diagnostico){
        return diagnosticoRepositorio.save(diagnostico);
    }

    public List<Diagnostico> getTodosDiagnosticos(){
        return diagnosticoRepositorio.findAll();
    }


    //---mapeo autoamtico
    public List<DiagnosticoDto> getTodosDiagnosticosDtos(){

        //creo dos listas una de pacientes y otra de DTos
        List<Diagnostico> listaDiagnostico = diagnosticoRepositorio.findAll();
        List<DiagnosticoDto> listaDiagnosticoDtos = new ArrayList<>();

        //creo un modeloMapper y luego le digo que la estrategia es stricta,
        // para que solamente copie los elementos que se llaman igual
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);

        //añadimos a la lista pacienteDto los datos de la lista Paciente
        for(Diagnostico diagnosticos : listaDiagnostico ){
            listaDiagnosticoDtos.add(modelMapper.map(diagnosticos, DiagnosticoDto.class));
        }

        return listaDiagnosticoDtos;
    }

}

package com.example.pruebados.service;

import com.example.pruebados.Dtos.dto.MedicoDto;
import com.example.pruebados.modelo.Medico;
import com.example.pruebados.repositorio.MedicoRepositorio;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class MedicoServicio {

    private final MedicoRepositorio medicoRepositorio;
    // es el constructor
    public MedicoServicio(MedicoRepositorio medicoRepositorio) {
        this.medicoRepositorio = medicoRepositorio;
    }
    //aqui los metodos
    public Medico crearMedico(Medico medico){
        return medicoRepositorio.save(medico);
    }

    public List<Medico> getTodosMedicos(){
        return medicoRepositorio.findAll();
    }
    //metodo que te devuelve el id del medico

    public Optional<Medico> getMedicoById(Integer id){
        return medicoRepositorio.findById(id);}

    public  Medico guardarMedicoLista(Medico medico){
        return medicoRepositorio.save(medico);
    }

    //---mapeo autoamitoco
    public List<MedicoDto> getTodosLosMedicosDtos(){

        //creo dos listas una de pacientes y otra de DTos
        List<Medico> listaMedicos = medicoRepositorio.findAll();
        List<MedicoDto> listaMedicosDtos = new ArrayList<>();

        //creo un modeloMapper y luego le digo que la estrategia es stricta,
        // para que solamente copie los elementos que se llaman igual
        ModelMapper modelMapper = new ModelMapper();
        modelMapper.getConfiguration().setMatchingStrategy(MatchingStrategies.STRICT);

        //añadimos a la lista pacienteDto los datos de la lista Paciente
        for(Medico medicos: listaMedicos ){
            listaMedicosDtos.add(modelMapper.map(medicos, MedicoDto.class));
        }

        return listaMedicosDtos;
    }
}

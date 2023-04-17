package com.example.pruebados.InterfazMapperDto;

import com.example.pruebados.Dtos.interfazDto.InterfazPacienteDto;
import org.mapstruct.factory.Mappers;

public class InterfazMapperDto {

    private InterfazPacienteDto mapper = Mappers.getMapper(InterfazPacienteDto.class);

    public void pacienteMapperTest(){

    }

}

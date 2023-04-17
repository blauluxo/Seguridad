package com.example.pruebados.Dtos.interfazDto;

import com.example.pruebados.Dtos.dto.PacienteDto;
import com.example.pruebados.modelo.Paciente;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper
public interface InterfazPacienteDto {

    Paciente pacienteToPacienteDto (PacienteDto pacienteDto);
    PacienteDto pacienteDtoToPaciente (Paciente paciente);
}

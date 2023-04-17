package com.example.pruebados.restApi;

import com.example.pruebados.modelo.Medico;
import com.example.pruebados.modelo.Paciente;
import com.example.pruebados.service.MedicoServicio;
import com.example.pruebados.service.PacienteServicio;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.NoSuchElementException;
import java.util.Optional;

@RestController
    @RequestMapping("/api/pacientemedico")
public class PacienteMedicoControlador {


    private final PacienteServicio pacienteServicio;
    private final MedicoServicio medicoServicio;

    public PacienteMedicoControlador(PacienteServicio pacienteServicio, MedicoServicio medicoServicio) {
        this.pacienteServicio = pacienteServicio;
        this.medicoServicio = medicoServicio;
    }


    //aqui lo que hacemos es añadir un paciente al medico
    @PutMapping("/{medicoId}/{pacienteId}")
    public Medico agregarPacienteAMedico(@PathVariable Integer medicoId, @PathVariable Integer pacienteId) {

        //buscamos por el id el medico y el servicio
        Optional<Medico> medico = medicoServicio.getMedicoById(medicoId);
        Optional<Paciente> pacientes = pacienteServicio.getPacienteById(pacienteId);

        //convertimos los pacientes y medicos
        Paciente pacienteNuevo = pacientes.orElseThrow();
        Medico medicoeNuevo = medico.orElseThrow();

        //guardamos en la lista de medico el paciente y viceversa para que los 2 tengan
        medicoeNuevo.añadirPaciente(pacienteNuevo, medicoeNuevo);

        return medicoServicio.guardarMedicoLista(medicoeNuevo);

    }


}

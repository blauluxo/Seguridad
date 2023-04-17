package com.example.pruebados.security;

import com.example.pruebados.modelo.Paciente;
import com.example.pruebados.repositorio.PacienteRepositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class  UserDetailServiceImpl implements UserDetailsService {

    //esto lo que hace es cargar un repositorio¿PORQUE?
    @Autowired
    private PacienteRepositorio pacienteRepositorio;

  public UserDetails loadUserByUsername (String email) throws UsernameNotFoundException {
     Paciente paciente = pacienteRepositorio.findOneByEmail(email)
              .orElseThrow(()->new UsernameNotFoundException("El usuario con email: "+email+" no existe"));

     return new UserDetailsImpl(paciente);
  }

}

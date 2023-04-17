package com.example.pruebados.security;

import com.example.pruebados.modelo.Paciente;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {

    private final Paciente paciente;

    public String getNombre(){
        return paciente.getNombre();
    }

    //este metodo seria util si nuestro paciente tuviera permiso o roles.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList() ;
    }
    //retorna una contraseña
    @Override
    public String getPassword() {
        return paciente.getPassword();
    }
    //me devuelve el getEmail, porque es el username
    @Override
    public String getUsername() {
        return paciente.getEmail();
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
}

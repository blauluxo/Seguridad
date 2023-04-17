package com.example.pruebados.service;

import com.example.pruebados.modelo.Usuario;
import com.example.pruebados.repositorio.UsuarioRepositorio;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.List;
import java.util.Optional;

@Service
public class usuarioServicio {

    private final UsuarioRepositorio usuarioRepositorio;
//es el constructor
    public usuarioServicio(UsuarioRepositorio usuarioRepositorio) {
        this.usuarioRepositorio = usuarioRepositorio;
    }
//aqui los metodos
    public Usuario crearUsuario(Usuario usuario){
         return usuarioRepositorio.save(usuario);
    }

    public Usuario getUsuariobyID(Integer id){
        return usuarioRepositorio.findById(id).get();
    }

    public Usuario getUsuariobyNombre(String nombre){
        return usuarioRepositorio.findByNombre(nombre);
    }

    public List<Usuario> getTodosUsuarios (){
        return usuarioRepositorio.findAll();
    }




    @DeleteMapping//("/{id}")
    public void borrarUsuario(@PathVariable Integer id) {
        Optional<Usuario> optionalUsuario = usuarioRepositorio.findById(id);
        if (optionalUsuario.isPresent()) {
            Usuario usuarioAEliminar = optionalUsuario.get();
            usuarioRepositorio.delete(usuarioAEliminar);
            System.out.println("Usuario eliminado correctamente");
        } else {
            System.out.println("No se encontró ningún usuario con ese ID");
        }
    }


}

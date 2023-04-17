package com.example.pruebados.restApi;

import com.example.pruebados.modelo.Usuario;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/usuarios")
public class UsuarioControlador {

    private final com.example.pruebados.service.usuarioServicio usuarioServicio;

    public UsuarioControlador(com.example.pruebados.service.usuarioServicio usuarioServicio) {
        this.usuarioServicio = usuarioServicio;
    }

    @PostMapping("/anadir")
    public Usuario crearUsuario(@RequestBody Usuario usuarios){
        return usuarioServicio.crearUsuario(usuarios);
    }

    @GetMapping("/{id}")
    public Usuario getUsuarioByID(@PathVariable Integer id) {
        return usuarioServicio.getUsuariobyID(id);
    }
    @GetMapping("/lista")
    public List<Usuario> getTodosUsuarios(){
        return usuarioServicio.getTodosUsuarios();
    }
    @GetMapping("/{nombre}")
    public Usuario getUsuariobyNombre(@PathVariable String nombre) {
        return usuarioServicio.getUsuariobyNombre(nombre);
    }

    @DeleteMapping("/borrar/{id}")
    public void borrarUsuario(@PathVariable Integer id) {
        usuarioServicio.borrarUsuario(id);
    }

}

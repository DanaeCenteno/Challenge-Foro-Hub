package com.alura.forohub.controller;

import com.alura.forohub.domain.topico.Topico;
import com.alura.forohub.domain.usuario.DatosRegistroUsuario;
import com.alura.forohub.domain.usuario.Usuario;
import com.alura.forohub.domain.usuario.UsuarioRepository;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/login")
public class UsuarioController {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @PostMapping
    public void registrarUsuario(@RequestBody @Valid DatosRegistroUsuario datosRegistroUsuario){
      usuarioRepository.save(new Usuario(datosRegistroUsuario));
    }

    @GetMapping
    public List<Usuario> listadoUsuario(){
        return  usuarioRepository.findAll();
    }
}

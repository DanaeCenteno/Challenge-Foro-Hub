package com.alura.forohub.controller;

import com.alura.forohub.domain.topico.*;
import com.alura.forohub.domain.usuario.Usuario;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Optional;


@RestController
@RequestMapping("/topicos")
public class TopicoController {

    @Autowired
    private TopicoRespository topicoRespository;

        //REGISTRAR LOS DATOS
    @PostMapping
    public ResponseEntity registrarTopico(@RequestBody @Valid DatosRegistroTopico datosRegistroTopico, UriComponentsBuilder uriComponentsBuilder){
      Topico topico =   topicoRespository.save(new Topico(datosRegistroTopico));
        DatosRespuestaTopico  datosRespuestaTopico = new DatosRespuestaTopico(
                        topico.getId(),
                        topico.getTitulo(),
                        topico.getMensaje(),
                        topico.getFecha_creacion(),
                        topico.isStatus(),
                        topico.getAutor(),
                        topico.getNombre_curso());
        URI url = uriComponentsBuilder.path("/topicos/{id}").buildAndExpand(topico.getId()).toUri();

       return ResponseEntity.created(url).body(datosRespuestaTopico);
    }


        //LISTAR REGISTROS TOPICOS
    @GetMapping
    public ResponseEntity<Page<DatosListadoTopico>> listadoTopico(@PageableDefault(size = 10) Pageable paginacion){
        return ResponseEntity.ok(topicoRespository.findByStatusTrue(paginacion).map(DatosListadoTopico::new));
    }


        //ACTUALIZACION  REGISTRO TOPICO
    @PutMapping
    @Transactional
    public ResponseEntity ActualizarTopico(@RequestBody @Valid ActualizarTopico actualizarTopico){
        Topico topico= topicoRespository.getReferenceById(actualizarTopico.id());
        topico.actualizarDatos(actualizarTopico);
        return  ResponseEntity.ok(new DatosRespuestaTopico(
               topico.getId(),
                topico.getTitulo(),
                topico.getMensaje(),
                topico.getFecha_creacion(),
                topico.isStatus(),
                topico.getAutor(),
                topico.getNombre_curso()
        ));
    }

        //BORRAR REGISTRO TOPICO
    @DeleteMapping("/{id}")
    public ResponseEntity eliminarTopico(@PathVariable Long id){
     //   Topico topico= topicoRespository.getReferenceById(id);
        Optional<Topico> optionalTopico = topicoRespository.findById(id);

        if(optionalTopico.isPresent()){
            Topico topico = optionalTopico.get();
            topico.desactivarTopico();
            topicoRespository.deleteById(id);

        }else {
            throw new EntityNotFoundException("No se encontro el topico con id: " + id);
        }

        return ResponseEntity.noContent().build();
    }

    //BORRAR REGISTRO TOPICO
    @GetMapping("/{id}")
    public ResponseEntity<DatosRespuestaTopico> retornaDatosTopico(@PathVariable Long id){
           Topico topico= topicoRespository.getReferenceById(id);
       var datosTopico = new DatosRespuestaTopico(
               topico.getId(),
               topico.getTitulo(),
               topico.getMensaje(),
               topico.getFecha_creacion(),
               topico.isStatus(),
               topico.getAutor(),
               topico.getNombre_curso()
       );
        return ResponseEntity.ok(datosTopico);
    }
}

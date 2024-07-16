package com.alura.forohub.domain.topico;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Table(name = "topicos")
@Entity(name = "Topico")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Topico {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String titulo;
    private String mensaje;
    @Enumerated(EnumType.STRING)
    @Column(name = "nombreCurso")
    private Curso nombre_curso;
    private LocalDateTime fecha_creacion;

    private boolean status;

    private String autor;


    public Topico(DatosRegistroTopico datosRegistroTopico) {
        this.titulo = datosRegistroTopico.titulo();
        this.mensaje = datosRegistroTopico.mensaje();
        this.nombre_curso = datosRegistroTopico.nombreCurso();
        this.autor = datosRegistroTopico.autor();
        this.fecha_creacion = LocalDateTime.now();
        this.status = true;
    }

    public void actualizarDatos(ActualizarTopico actualizarTopico) {

        if (actualizarTopico.titulo() != null) {
            this.titulo = actualizarTopico.titulo();
        }
        if (actualizarTopico.mensaje() != null) {
            this.mensaje = actualizarTopico.mensaje();
        }
        if (actualizarTopico.nombreCurso() != null) {
            this.nombre_curso = Curso.valueOf(actualizarTopico.nombreCurso());
        }

    }

    public void desactivarTopico(){
        this.status = false;
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitulo() {
        return titulo;
    }

    public void setTitulo(String titulo) {
        this.titulo = titulo;
    }

    public String getMensaje() {
        return mensaje;
    }

    public void setMensaje(String mensaje) {
        this.mensaje = mensaje;
    }

    public Curso getNombre_curso() {
        return nombre_curso;
    }

    public void setNombre_curso(Curso nombre_curso) {
        this.nombre_curso = nombre_curso;
    }

    public LocalDateTime getFecha_creacion() {
        return fecha_creacion;
    }

    public void setFecha_creacion(LocalDateTime fecha_creacion) {
        this.fecha_creacion = fecha_creacion;
    }

    public boolean isStatus() {
        return status;
    }

    public void setStatus(boolean status) {
        this.status = status;
    }

    public String getAutor() {
        return autor;
    }

    public void setAutor(String autor) {
        this.autor = autor;
    }
}

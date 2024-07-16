package com.alura.forohub.domain.topico;

import jakarta.validation.constraints.NotNull;

public record ActualizarTopico(
       @NotNull
        Long id,
        String titulo,
        String mensaje,
        String nombreCurso,
        boolean status

) {
}

package com.alura.forohub.domain.topico;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record DatosRegistroTopico(
        @NotBlank
        String autor,
        @NotBlank
        String titulo,
        @NotBlank
        String mensaje,

        @Valid
        @NotNull
        Curso nombreCurso
) {
}

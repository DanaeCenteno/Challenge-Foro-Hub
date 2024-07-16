//lo que recibe de la API
package com.alura.forohub.domain.usuario;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record DatosRegistroUsuario(
        @NotBlank
        @Email
        String email,
        @NotBlank
        String clave
) {
}

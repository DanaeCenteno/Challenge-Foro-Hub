# FORO HUB -AluraLatam


# Descripción
En este programa se desarrolla una API sobre un Foro en el que se los usuarios pueden registrarse  mediante un correo y una clave ademas, se pueden crear, eliminar, registrar y actualizar topicos.

Mediante Bcrypt codifica las claves para de lod usuarios mediante tokens para validarlos y asi manejar la seguridad del usuario.


## Tecnologías Implementadas


- Spring Boot
- Spring Security
- JWT
- JPA
- MySQL
- Lombok
- FlyWay
- Maven v4

### Tratamiento de Errores

- Se utilizo la propiedad server.error.include-stacktrace para la protección de informacion sencible. Se utilzaron clases para los diferentes manejos de errores que lanzan las excepciones de validacion de datos.

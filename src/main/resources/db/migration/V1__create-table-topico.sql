create table topicos (
        id bigint not null auto_increment,
        titulo varchar(200) not null,
        mensaje varchar(500) not null,
        fecha_creacion datetime not null,
        status tinyint not null,
        autor varchar(100) not null,
        nombre_curso varchar(100) not null,

        primary key(id)
);
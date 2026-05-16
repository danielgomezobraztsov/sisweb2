# Modelo de datos

La base de datos MongoDB se llama `vulnsdb`.

## Colección `vulnerabilities`

Representa vulnerabilidades de seguridad.

Campos principales:

- `cve`: identificador CVE.
- `title`: título de la vulnerabilidad.
- `description`: descripción de la vulnerabilidad.
- `severity`: nivel de severidad. Valores permitidos: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `publishedDate`: fecha de publicación.
- `source`: origen del dato. Puede ser `seed`, `internal`, `nvd` o `xml-feed`.
- `systems`: referencias a documentos de la colección `systems`.
- `applications`: referencias a documentos de la colección `applications`.

## Colección `systems`

Representa sistemas operativos afectados.

Campos principales:

- `name`: nombre del sistema.
- `os`: familia del sistema operativo.
- `version`: versión del sistema.

## Colección `applications`

Representa aplicaciones afectadas.

Campos principales:

- `name`: nombre de la aplicación.
- `vendor`: fabricante o proveedor.
- `version`: versión de la aplicación.

## Relaciones

- Una vulnerabilidad puede afectar a varios sistemas.
- Una vulnerabilidad puede afectar a varias aplicaciones.
- Cada recurso se guarda en una colección independiente.

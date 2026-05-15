# Vulnerabilities API

API REST para consultar, registrar y gestionar vulnerabilidades conocidas en sistemas **Windows** y **Linux** (CVEs).

## Miembros del grupo

> Rellenar aquí los nombres del grupo antes de la entrega.

## Estructura del proyecto

```
vulns-api/
├── src/
│   ├── app.js                 # Configuración Express
│   ├── server.js              # Punto de entrada
│   ├── config/db.js           # Conexión MongoDB
│   ├── models/
│   │   ├── Vuln.js            # Colección vulns (1200+ docs)
│   │   ├── Application.js     # Colección applications
│   │   └── ApiKey.js          # Colección apikeys (autenticación)
│   ├── routes/vulns.js        # Router principal
│   ├── controllers/vulnController.js
│   ├── middleware/
│   │   ├── auth.js            # Autenticación por X-API-Key
│   │   └── parseXml.js        # Parser de cuerpos XML
│   ├── services/externalApi.js  # Integración NVD + CISA
│   └── utils/xmlUtils.js      # Serialización XML/JSON
├── scripts/
│   ├── generateDataset.js     # Genera data/vulns.json (1200 entradas)
│   └── loadData.js            # Carga los datos en MongoDB
├── data/
│   ├── vulns.json             # 1200 vulnerabilidades (generado)
│   └── applications.json      # 25 aplicaciones de referencia
├── schemas/vuln.xsd           # XML Schema para validación
├── docs/                      # Documentación adicional
└── OpenAPI.yaml               # Descripción del servicio
```

## Instalación y puesta en marcha

### Requisitos previos
- Node.js >= 18
- MongoDB >= 6 (local o Atlas)

### 1. Clonar e instalar dependencias
```bash
git clone <url-del-repo>
cd vulns-api
npm install
```

### 2. Configurar variables de entorno
```bash
cp .env.example .env
# Editar .env con tus valores:
# - MONGODB_URI (por defecto: mongodb://localhost:27017/vulnsdb)
# - API_KEY     (clave para operaciones de escritura)
# - NVD_API_KEY (opcional, mejora el rate limit de la NVD)
```

### 3. Cargar los datos iniciales
```bash
# Opción A: todo en un paso
npm run setup

# Opción B: paso a paso
npm run generate-dataset   # genera data/vulns.json con 1200 CVEs
npm run load-data          # importa a MongoDB (limpia colecciones primero)
```

### 4. Arrancar el servidor
```bash
npm start          # producción
npm run dev        # desarrollo con auto-reload (nodemon)
```

El servidor arrancará en `http://localhost:3000`.

---

## Endpoints

Todos los endpoints soportan respuesta en **JSON** (por defecto) o **XML** (con `Accept: application/xml`).  
Los endpoints de escritura (POST, PUT, DELETE) requieren el header `X-API-Key`.

### Vulnerabilidades

| Método | Ruta | Descripción | Auth |
|--------|------|-------------|------|
| `GET`  | `/vulns` | Lista paginada con filtros | No |
| `POST` | `/vulns` | Crear nueva vulnerabilidad | SI |
| `GET`  | `/vulns/:id` | Detalle por CVE-ID | No |
| `PUT`  | `/vulns/:id` | Actualización completa | SI |
| `DELETE` | `/vulns/:id` | Eliminar por CVE-ID | SI |
| `GET`  | `/vulns/os/:os` | Filtrar por OS | No |
| `GET`  | `/vulns/os/:os/version/:version` | Filtrar por OS+versión | No |
| `GET`  | `/vulns/apps` | Vulnerabilidades de aplicaciones | No |
| `GET`  | `/vulns/apps/:id` | Detalle de vuln de app | No |

### Parámetros de query (GET /vulns)

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `page` | integer (≥1) | Página (default: 1) |
| `numElements` | integer (1-50) | Elementos por página (default: 10) |
| `os` | `windows` \| `linux` | Filtrar por OS |
| `severity` | `LOW` \| `MEDIUM` \| `HIGH` \| `CRITICAL` | Filtrar por severidad |
| `version` | ver enum en OpenAPI.yaml | Filtrar por versión |
| `cveId` | string CVE-YYYY-XXXXX | Búsqueda exacta por ID |

---

## Autenticación

Las operaciones de escritura requieren el header:
```
X-API-Key: <tu-api-key>
```

La clave por defecto en desarrollo se configura en `API_KEY` del `.env`.

---

## Formatos de mensaje

### JSON (por defecto)

**POST /vulns** — Cuerpo de ejemplo:
```json
{
  "id": "CVE-2024-99999",
  "titulo": "Windows Kernel Elevation of Privilege Vulnerability",
  "descripcion": "A vulnerability in the Windows Kernel allows an attacker...",
  "os": "windows",
  "version": "windows-11",
  "tipoVuln": "EoP",
  "severity": "HIGH",
  "cvss": {
    "version": "3.1",
    "score": 7.8,
    "severity": "HIGH",
    "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
  },
  "fechaPublicacion": "2024-07-09",
  "explotadaActivamente": false,
  "fuente": "MSRC",
  "urlParche": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-99999"
}
```

### XML — con `Content-Type: application/xml` y `Accept: application/xml`

**POST /vulns** — Cuerpo XML validado contra `schemas/vuln.xsd`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<vuln>
  <id>CVE-2024-99999</id>
  <titulo>Windows Kernel Elevation of Privilege Vulnerability</titulo>
  <descripcion>A vulnerability in the Windows Kernel allows an attacker...</descripcion>
  <os>windows</os>
  <version>windows-11</version>
  <tipoVuln>EoP</tipoVuln>
  <severity>HIGH</severity>
  <cvss>
    <version>3.1</version>
    <score>7.8</score>
    <severity>HIGH</severity>
    <vector>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</vector>
  </cvss>
  <fechaPublicacion>2024-07-09</fechaPublicacion>
  <explotadaActivamente>false</explotadaActivamente>
  <fuente>MSRC</fuente>
  <urlParche>https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-99999</urlParche>
</vuln>
```

---

## APIs externas integradas

La API sincroniza datos en segundo plano desde dos fuentes externas.  
**Si alguna API externa está caída, la API sigue funcionando normalmente con los datos locales.**

| API | Formato | URL | Descripción |
|-----|---------|-----|-------------|
| **NVD CVE API v2** | **JSON** | `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVEs publicados en las últimas 24h |
| **CISA RSS Feed** | **XML** | `https://www.cisa.gov/cybersecurity-advisories/all.xml` | Marca CVEs como explotados activamente |

La sincronización se lanza al arrancar (con 5s de retardo) y cada hora.  
Para NVD: registrarse en https://nvd.nist.gov/developers/request-an-api-key para obtener un API key (mayor rate limit).

---

## Modelo de datos (MongoDB)

### Colección `vulns` (principal, 1200+ docs)
Campos: `id`, `titulo`, `descripcion`, `os`, `version`, `tipoVuln`, `severity`, `cvss`, `fechaPublicacion`, `fechaActualizacion`, `explotadaActivamente`, `fuente`, `urlParche`, `referencias`, `isAppVuln`

### Colección `applications` (25 apps)
Campos: `name`, `vendor`, `version`, `category`, `os`, `description`

### Colección `apikeys` (autenticación)
Campos: `key`, `name`, `active`, `usages`, `lastUsed`

---

## Ejemplos de uso con curl

```bash
# Listar vulnerabilidades críticas de Windows (página 1)
curl "http://localhost:3000/vulns?os=windows&severity=CRITICAL&page=1&numElements=5"

# Obtener detalle de una vulnerabilidad
curl "http://localhost:3000/vulns/CVE-2024-21338"

# Listar vulnerabilidades de Ubuntu
curl "http://localhost:3000/vulns/os/linux/version/ubuntu"

# Crear una vulnerabilidad (requiere X-API-Key)
curl -X POST http://localhost:3000/vulns \
  -H "Content-Type: application/json" \
  -H "X-API-Key: dev-api-key-12345" \
  -d '{ "id": "CVE-2024-99998", ... }'

# Crear con XML
curl -X POST http://localhost:3000/vulns \
  -H "Content-Type: application/xml" \
  -H "Accept: application/xml" \
  -H "X-API-Key: dev-api-key-12345" \
  -d '<vuln><id>CVE-2024-99998</id>...</vuln>'

# Eliminar
curl -X DELETE http://localhost:3000/vulns/CVE-2024-99998 \
  -H "X-API-Key: dev-api-key-12345"
```

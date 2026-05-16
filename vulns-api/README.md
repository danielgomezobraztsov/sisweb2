# Vulnerability API

REST API developed in Node.js using MongoDB Atlas.

## Group members

Add the names of the group members here.

## Theme

The project is a vulnerability management API for Windows and Linux systems.

## Technologies

- Node.js
- Express
- MongoDB Atlas
- Mongoose
- OpenAPI
- JSON
- XML

## Installation

```bash
npm install
```

## Environment variables

Copy `.env.example` into `.env` and replace the MongoDB URI with your real URI.

```bash
cp .env.example .env
```

Example:

```env
PORT=3000
MONGO_URI=mongodb+srv://USER:PASSWORD@cluster0.q3bnlfm.mongodb.net/vulnsdb?retryWrites=true&w=majority&appName=Cluster0
```

## Run the project

```bash
npm run dev
```

Or:

```bash
npm start
```

## Load initial data

This command creates systems, applications and 1000 vulnerabilities.

```bash
npm run seed
```

It also generates the file `data/vulnerabilities.json`.

## Main routes

### Vulnerabilities

- `GET /vulns`
- `GET /vulns?page=1&limit=10`
- `GET /vulns?severity=HIGH`
- `GET /vulns?search=windows`
- `GET /vulns/:id`
- `POST /vulns`
- `PUT /vulns/:id`
- `DELETE /vulns/:id`
- `GET /vulns/import/json`
- `GET /vulns/import/xml`

### Systems

- `GET /systems`
- `GET /systems/:id`
- `POST /systems`
- `PUT /systems/:id`
- `DELETE /systems/:id`

### Applications

- `GET /applications`
- `GET /applications/:id`
- `POST /applications`
- `PUT /applications/:id`
- `DELETE /applications/:id`

## External APIs

The project consumes the NVD API as an external JSON API.

The project also consumes an external XML feed and parses it with `xml2js`.

If an external API is unavailable, the API returns cached data already stored in MongoDB when possible.

## Documentation

- OpenAPI file: `docs/OpenAPI.yaml`
- XML schema: `docs/vulnerability.xsd`
- Data model: `docs/modelo-datos.md`

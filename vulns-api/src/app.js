require("dotenv").config();

const express = require("express");
const cors = require("cors");

const connectDB = require("./db");
const vulnRoutes = require("./routes/vuln.routes");

const app = express();

connectDB();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use("/vulns", vulnRoutes);

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return res.status(422).json({
      codigo: 422,
      texto: "JSON incorrecto",
      descripcion: err.message
    });
  }

  return res.status(500).json({
    codigo: 500,
    texto: "Error interno",
    descripcion: err.message
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
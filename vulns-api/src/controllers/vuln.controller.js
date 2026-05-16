const Vulnerability = require("../models/Vulnerability");

function buildMessage(codigo, texto, descripcion) {
  return { codigo, texto, descripcion };
}

function toVulnMin(vuln) {
  return {
    id: vuln.id,
    titulo: vuln.titulo,
    os: vuln.os,
    version: vuln.version,
    severity: vuln.severity,
    fechaPublicacion: vuln.fechaPublicacion,
    explotadaActivamente: vuln.explotadaActivamente
  };
}

function buildPagination(req) {
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const numElements = Math.min(
    Math.max(parseInt(req.query.numElements) || 10, 1),
    50
  );

  return { page, numElements };
}

function buildBaseFilter(req) {
  const filter = {};

  if (req.query.os) {
    filter.os = req.query.os;
  }

  if (req.query.severity) {
    filter.severity = req.query.severity.toUpperCase();
  }

  if (req.query.version) {
    filter.version = req.query.version;
  }

  if (req.query.cveId) {
    filter.id = req.query.cveId;
  }

  return filter;
}

exports.getAllVulns = async (req, res) => {
  try {
    const { page, numElements } = buildPagination(req);
    const filter = buildBaseFilter(req);

    const vulns = await Vulnerability.find(filter)
      .sort({ fechaPublicacion: -1 })
      .skip((page - 1) * numElements)
      .limit(numElements);

    res.json(vulns.map(toVulnMin));
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.getVulnById = async (req, res) => {
  try {
    const vuln = await Vulnerability.findOne({ id: req.params.id });

    if (!vuln) {
      return res.status(404).json(
        buildMessage(
          404,
          "No existe una vulnerabilidad con ese ID",
          "El CVE-ID proporcionado no se encontró en la base de datos"
        )
      );
    }

    res.json(vuln);
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.createVuln = async (req, res) => {
  try {
    const vuln = await Vulnerability.create(req.body);

    res.status(201).json(
      buildMessage(
        201,
        "Vulnerabilidad creada correctamente",
        vuln.id
      )
    );
  } catch (error) {
    res.status(400).json(
      buildMessage(400, "Formato incorrecto", error.message)
    );
  }
};

exports.updateVuln = async (req, res) => {
  try {
    const vuln = await Vulnerability.findOneAndUpdate(
      { id: req.params.id },
      req.body,
      {
        new: true,
        runValidators: true
      }
    );

    if (!vuln) {
      return res.status(404).json(
        buildMessage(
          404,
          "No existe una vulnerabilidad con ese ID",
          "El CVE-ID proporcionado no se encontró en la base de datos"
        )
      );
    }

    res.json(
      buildMessage(
        200,
        "Vulnerabilidad actualizada correctamente",
        vuln.id
      )
    );
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "JSON incorrecto", error.message)
    );
  }
};

exports.deleteVuln = async (req, res) => {
  try {
    const vuln = await Vulnerability.findOneAndDelete({
      id: req.params.id
    });

    if (!vuln) {
      return res.status(404).json(
        buildMessage(
          404,
          "No existe una vulnerabilidad con ese ID",
          "El CVE-ID proporcionado no se encontró en la base de datos"
        )
      );
    }

    res.status(204).send();
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.getVulnsByOs = async (req, res) => {
  try {
    const { os } = req.params;

    if (!["windows", "linux"].includes(os)) {
      return res.status(404).json(
        buildMessage(404, "OS no reconocido", "El sistema operativo no es válido")
      );
    }

    const { page, numElements } = buildPagination(req);

    const filter = {
      ...buildBaseFilter(req),
      os
    };

    const vulns = await Vulnerability.find(filter)
      .sort({ fechaPublicacion: -1 })
      .skip((page - 1) * numElements)
      .limit(numElements);

    res.json(vulns.map(toVulnMin));
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.getVulnsByOsAndVersion = async (req, res) => {
  try {
    const { os, version } = req.params;

    if (!["windows", "linux"].includes(os)) {
      return res.status(404).json(
        buildMessage(404, "OS o versión no reconocidos", "El sistema operativo no es válido")
      );
    }

    const { page, numElements } = buildPagination(req);

    const filter = {
      ...buildBaseFilter(req),
      os,
      version
    };

    const vulns = await Vulnerability.find(filter)
      .sort({ fechaPublicacion: -1 })
      .skip((page - 1) * numElements)
      .limit(numElements);

    res.json(vulns.map(toVulnMin));
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.getAppVulns = async (req, res) => {
  try {
    const { page, numElements } = buildPagination(req);

    const filter = {
      ...buildBaseFilter(req),
      isAppVuln: true
    };

    const vulns = await Vulnerability.find(filter)
      .sort({ fechaPublicacion: -1 })
      .skip((page - 1) * numElements)
      .limit(numElements);

    res.json(vulns.map(toVulnMin));
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};

exports.getAppVulnById = async (req, res) => {
  try {
    const vuln = await Vulnerability.findOne({
      id: req.params.id,
      isAppVuln: true
    });

    if (!vuln) {
      return res.status(404).json(
        buildMessage(
          404,
          "No existe una vulnerabilidad de aplicación con ese ID",
          "El CVE-ID proporcionado no se encontró como vulnerabilidad de aplicación"
        )
      );
    }

    res.json(vuln);
  } catch (error) {
    res.status(422).json(
      buildMessage(422, "Parámetros incorrectos", error.message)
    );
  }
};
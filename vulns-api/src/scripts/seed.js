require("dotenv").config();

const mongoose = require("mongoose");
const axios = require("axios");
const Vulnerability = require("../models/Vulnerability");

function getSeverity(metrics) {
  if (metrics?.cvssMetricV31?.[0]) return metrics.cvssMetricV31[0].cvssData;
  if (metrics?.cvssMetricV30?.[0]) return metrics.cvssMetricV30[0].cvssData;
  if (metrics?.cvssMetricV2?.[0]) return metrics.cvssMetricV2[0].cvssData;
  return null;
}

async function seed() {
  try {
    await mongoose.connect(process.env.MONGO_URI);

    await Vulnerability.deleteMany({ fuente: "NVD" });

    const response = await axios.get(
      "https://services.nvd.nist.gov/rest/json/cves/2.0",
      {
        params: {
          resultsPerPage: 2000,
          keywordSearch: "windows linux"
        }
      }
    );

    const docs = response.data.vulnerabilities.map((item) => {
      const cve = item.cve;
      const cvssData = getSeverity(cve.metrics);

      const description =
        cve.descriptions.find((d) => d.lang === "en")?.value ||
        "No description available";

      const cveId = cve.id;

      return {
        id: cveId,
        titulo: cveId,
        descripcion: description,
        os: description.toLowerCase().includes("windows") ? "windows" : "linux",
        version: description.toLowerCase().includes("windows")
          ? "windows"
          : "linux",
        tipoVuln: "Unknown",
        severity: cvssData?.baseSeverity || "MEDIUM",

        cvss: {
          version: cvssData?.version || "3.1",
          score: cvssData?.baseScore || 5.0,
          severity: cvssData?.baseSeverity || "MEDIUM",
          vector: cvssData?.vectorString || "N/A"
        },

        fechaPublicacion: cve.published,
        fechaActualizacion: cve.lastModified,
        explotadaActivamente: false,
        fuente: "NVD",
        urlParche: cve.references?.referenceData?.[0]?.url || "",
        referencias: cve.references?.referenceData?.map((r) => r.url) || [],
        isAppVuln: false
      };
    });

    await Vulnerability.insertMany(docs, { ordered: false });

    console.log(`Inserted ${docs.length} real vulnerabilities from NVD`);
    process.exit(0);
  } catch (error) {
    console.error("Seed error:", error.message);
    process.exit(1);
  }
}

seed();
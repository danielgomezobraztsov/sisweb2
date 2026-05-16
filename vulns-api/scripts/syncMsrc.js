#!/usr/bin/env node
require("dotenv").config();

const mongoose = require("mongoose");
const {
  axios,
  createRun,
  finishRun,
  saveRaw,
  upsertVuln,
  inferTipo
} = require("./syncCommon");

const SOURCE = "MSRC";
const UPDATES_ENDPOINT = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";
const CVRF_ENDPOINT = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf";

function normalizeMsrcSeverity(value, score) {
  const text = String(value || "").toLowerCase();

  if (text.includes("critical")) return "CRITICAL";
  if (text.includes("important")) return "HIGH";
  if (text.includes("high")) return "HIGH";
  if (text.includes("moderate")) return "MEDIUM";
  if (text.includes("medium")) return "MEDIUM";
  if (text.includes("low")) return "LOW";

  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";

  return "LOW";
}

function getDescription(v, title) {
  const notes = v.Notes || [];
  return (
    notes.find(n => /description/i.test(String(n.Title || n.Type || "")))?.Value ||
    notes.find(n => String(n.Value || "").length > 20)?.Value ||
    title
  );
}

function mapMsrcVulnerability(v, releaseId) {
  const cveId = v.CVE;
  const title = v.Title?.Value || cveId;

  const description = getDescription(v, title);

  const scoreSet = v.CVSSScoreSets?.[0] || {};
  const parsedScore = Number(scoreSet.BaseScore);
  const baseScore = Number.isFinite(parsedScore) ? parsedScore : 7.5;

  const rawSeverity =
    v.Threats?.find(t => String(t.Type) === "3")?.Description?.Value ||
    v.Threats?.find(t => /severity/i.test(String(t.Type)))?.Description?.Value ||
    "";

  const severity = normalizeMsrcSeverity(rawSeverity, baseScore);

  const url =
    v.Remediations?.[0]?.URL ||
    `https://msrc.microsoft.com/update-guide/vulnerability/${cveId}`;

  return {
    id: cveId,
    titulo: title,
    descripcion: description,
    os: "windows",
    version: "windows-11",
    tipoVuln: inferTipo(`${title} ${description}`),
    severity,

    cvss: {
      version: "3.1",
      score: baseScore,
      severity,
      vector:
        scoreSet.Vector ||
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },

    fechaPublicacion: new Date(),
    fechaActualizacion: new Date(),

    explotadaActivamente: /exploited|exploitation detected|publicly disclosed/i.test(
      JSON.stringify(v.Threats || [])
    ),

    fuente: SOURCE,
    urlParche: url,
    referencias: [url, `https://nvd.nist.gov/vuln/detail/${cveId}`],
    isAppVuln: /office|edge|exchange|sharepoint|teams|visual studio/i.test(
      `${title} ${description}`
    )
  };
}

async function main() {
  const uri = process.env.MONGODB_URI || process.env.MONGO_URI;

  if (!uri) {
    throw new Error("Falta MONGODB_URI o MONGO_URI en .env");
  }

  await mongoose.connect(uri);

  const releaseLimit = Number(process.env.SYNC_MSRC_RELEASES || 3);

  const run = await createRun(SOURCE, UPDATES_ENDPOINT, { releaseLimit });

  const stats = {
    received: 0,
    rawSaved: 0,
    inserted: 0,
    updated: 0,
    skipped: 0,
    errors: 0
  };

  const errors = [];

  try {
    const updates = await axios.get(UPDATES_ENDPOINT, {
      timeout: 30000,
      headers: {
        Accept: "application/json"
      }
    });

    const releases = (updates.data.value || updates.data || [])
      .filter(x => x.ID || x.Id || x.id)
      .sort((a, b) => {
        const dateA = new Date(a.CurrentReleaseDate || a.InitialReleaseDate || 0);
        const dateB = new Date(b.CurrentReleaseDate || b.InitialReleaseDate || 0);
        return dateB - dateA;
      })
      .slice(0, releaseLimit);

    for (const release of releases) {
      const releaseId = release.ID || release.Id || release.id;
      const url = `${CVRF_ENDPOINT}/${releaseId}`;

      const response = await axios.get(url, {
        timeout: 30000,
        headers: {
          Accept: "application/json"
        }
      });

      console.log("MSRC release:", releaseId);

      const vulns = response.data.Vulnerability || [];
      stats.received += vulns.length;

      for (const vuln of vulns) {
        const cveId = vuln.CVE;

        if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
          stats.skipped++;
          continue;
        }

        try {
          const raw = await saveRaw(
            SOURCE,
            run,
            `${releaseId}:${cveId}`,
            cveId,
            url,
            {},
            vuln
          );

          if (raw) {
            stats.rawSaved++;
          }

          const normalized = mapMsrcVulnerability(vuln, releaseId);
          const result = await upsertVuln(normalized);

          if (result.inserted) {
            stats.inserted++;
          } else {
            stats.updated++;
          }

          if (raw) {
            await raw.updateOne({ $set: { normalized: true } });
          }
        } catch (err) {
          stats.errors++;
          console.error("Error guardando MSRC:", cveId, err.message);
          errors.push({ message: err.message, cveId });
        }
      }
    }

    await finishRun(
      run,
      stats.errors ? "partial" : "success",
      stats,
      errors
    );

    console.log(
      `MSRC sync OK. Recibidas: ${stats.received}. Insertadas: ${stats.inserted}. Actualizadas: ${stats.updated}. Errores: ${stats.errors}.`
    );
  } catch (err) {
    stats.errors++;
    errors.push({ message: err.message });

    await finishRun(run, "failed", stats, errors);

    throw err;
  } finally {
    await mongoose.disconnect();
  }
}

main().catch(err => {
  console.error("syncMsrc error:", err.message);
  process.exit(1);
});
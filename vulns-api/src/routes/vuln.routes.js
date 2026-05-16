const express = require("express");

const router = express.Router();
const auth = require("../middlewares/auth");

const {
  getAllVulns,
  getVulnById,
  createVuln,
  updateVuln,
  deleteVuln,
  getVulnsByOs,
  getVulnsByOsAndVersion,
  getAppVulns,
  getAppVulnById
} = require("../controllers/vuln.controller");

router.get("/", getAllVulns);
router.post("/", auth, createVuln);

router.get("/os/:os", getVulnsByOs);
router.get("/os/:os/version/:version", getVulnsByOsAndVersion);

router.get("/apps", getAppVulns);
router.get("/apps/:id", getAppVulnById);

router.get("/:id", getVulnById);
router.put("/:id", auth, updateVuln);
router.delete("/:id", auth, deleteVuln);

module.exports = router;

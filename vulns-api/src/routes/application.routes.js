const express = require("express");

const router = express.Router();

const {
  getApplications,
  getApplicationById,
  createApplication,
  updateApplication,
  deleteApplication
} = require("../controllers/application.controller");

router.get("/", getApplications);
router.get("/:id", getApplicationById);
router.post("/", createApplication);
router.put("/:id", updateApplication);
router.delete("/:id", deleteApplication);

module.exports = router;

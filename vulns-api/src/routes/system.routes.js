const express = require("express");

const router = express.Router();

const {
  getSystems,
  getSystemById,
  createSystem,
  updateSystem,
  deleteSystem
} = require("../controllers/system.controller");

router.get("/", getSystems);
router.get("/:id", getSystemById);
router.post("/", createSystem);
router.put("/:id", updateSystem);
router.delete("/:id", deleteSystem);

module.exports = router;

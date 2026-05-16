const System = require("../models/System");

exports.getSystems = async (req, res) => {
  try {
    const systems = await System.find();
    res.json(systems);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.getSystemById = async (req, res) => {
  try {
    const system = await System.findById(req.params.id);

    if (!system) {
      return res.status(404).json({ message: "System not found" });
    }

    res.json(system);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

exports.createSystem = async (req, res) => {
  try {
    const system = new System(req.body);
    await system.save();
    res.status(201).json(system);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

exports.updateSystem = async (req, res) => {
  try {
    const system = await System.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
      runValidators: true
    });

    if (!system) {
      return res.status(404).json({ message: "System not found" });
    }

    res.json(system);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

exports.deleteSystem = async (req, res) => {
  try {
    const system = await System.findByIdAndDelete(req.params.id);

    if (!system) {
      return res.status(404).json({ message: "System not found" });
    }

    res.json({ message: "System deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

const router = require('express').Router();
const ctrl   = require('../controllers/vulnController');
const auth   = require('../middleware/auth');

// ⚠️  IMPORTANTE: las rutas literales ANTES que /:id para evitar conflictos en Express

// ── /vulns/apps ───────────────────────────────────────────────────────────────
router.get('/apps',     ctrl.getApps);
router.get('/apps/:id', ctrl.getAppById);

// ── /vulns/os/:os  y  /vulns/os/:os/version/:version ─────────────────────────
router.get('/os/:os/version/:version', ctrl.getByOsVersion);
router.get('/os/:os',                  ctrl.getByOs);

// ── /vulns  (colección raíz) ──────────────────────────────────────────────────
router.get('/',    ctrl.getAll);
router.post('/',   auth, ctrl.create);

// ── /vulns/:id ────────────────────────────────────────────────────────────────
router.get('/:id',    ctrl.getById);
router.put('/:id',    auth, ctrl.update);
router.delete('/:id', auth, ctrl.remove);

module.exports = router;

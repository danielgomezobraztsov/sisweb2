const { XMLParser } = require('fast-xml-parser');

const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  parseTagValue: true,
  trimValues: true,
});

/**
 * Si el Content-Type es application/xml, lee el body en crudo,
 * lo parsea con fast-xml-parser y lo pone en req.body igual que haría express.json().
 * Si el XML es inválido, responde 400.
 */
function parseXmlBody(req, res, next) {
  const ct = req.headers['content-type'] || '';
  if (!ct.includes('application/xml') && !ct.includes('text/xml')) {
    return next();
  }

  let raw = '';
  req.setEncoding('utf8');
  req.on('data', chunk => { raw += chunk; });
  req.on('end', () => {
    if (!raw) return next();
    try {
      req.body = xmlParser.parse(raw);
      // Si el root element es <vuln>, "aplanamos" un nivel
      if (req.body.vuln) req.body = req.body.vuln;
      next();
    } catch (err) {
      return res.status(400).json({ codigo: 400, texto: 'XML malformado', descripcion: err.message });
    }
  });
  req.on('error', next);
}

module.exports = { parseXmlBody };

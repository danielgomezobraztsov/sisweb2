const { create } = require('xmlbuilder2');

/**
 * Convierte un objeto JS (o array) a XML string.
 * @param {object|Array} data
 * @param {string} rootName  nombre del elemento raíz
 * @param {string} itemName  nombre de cada item (si data es array)
 */
function toXml(data, rootName = 'response', itemName = 'item') {
  const doc = create({ version: '1.0', encoding: 'UTF-8' }).ele(rootName);
  buildNode(doc, data, itemName);
  return doc.end({ prettyPrint: true });
}

function buildNode(parent, data, itemName) {
  if (Array.isArray(data)) {
    for (const item of data) {
      const node = parent.ele(itemName);
      buildNode(node, item, 'item');
    }
  } else if (data !== null && typeof data === 'object') {
    for (const [key, value] of Object.entries(data)) {
      if (value === undefined || value === null) continue;
      if (Array.isArray(value)) {
        const arrNode = parent.ele(key);
        for (const v of value) {
          const itemNode = arrNode.ele('item');
          if (typeof v === 'object') buildNode(itemNode, v, 'item');
          else itemNode.txt(String(v));
        }
      } else if (typeof value === 'object' && !(value instanceof Date)) {
        buildNode(parent.ele(key), value, 'item');
      } else {
        parent.ele(key).txt(String(value instanceof Date ? value.toISOString().split('T')[0] : value));
      }
    }
  } else if (data !== null && data !== undefined) {
    parent.txt(String(data));
  }
}

/**
 * Middleware helper: envía la respuesta en JSON o XML según el header Accept.
 * Se añade a res para poder usarlo como res.send200(data) etc.
 */
function formatResponse(req, res, statusCode, data, xmlRootName = 'response', xmlItemName = 'vuln') {
  const accept = req.headers['accept'] || '';
  if (accept.includes('application/xml') || accept.includes('text/xml')) {
    res.status(statusCode).type('application/xml').send(toXml(data, xmlRootName, xmlItemName));
  } else {
    res.status(statusCode).json(data);
  }
}

module.exports = { toXml, formatResponse };

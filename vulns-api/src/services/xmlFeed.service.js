const axios = require("axios");
const xml2js = require("xml2js");

async function fetchXmlFeed() {
  try {
    const response = await axios.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.xml", {
      timeout: 10000
    });

    const parser = new xml2js.Parser({ explicitArray: false });
    return await parser.parseStringPromise(response.data);
  } catch (error) {
    console.error("XML API error:", error.message);
    return null;
  }
}

module.exports = {
  fetchXmlFeed
};

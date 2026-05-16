const axios = require("axios");

async function fetchNvdData() {
  try {
    const response = await axios.get("https://services.nvd.nist.gov/rest/json/cves/2.0", {
      timeout: 10000,
      params: {
        resultsPerPage: 20
      }
    });

    return response.data;
  } catch (error) {
    console.error("NVD API error:", error.message);
    return null;
  }
}

module.exports = {
  fetchNvdData
};

// Loaded by the Playwright MCP server (--init-page) for every tab the AI
// investigator opens. After each page load settles, it saves what the browser
// shows as browser/shot-<epoch ms>.jpg in the case's evidence folder (the
// server's working directory), so the live panel shows the AI's view as it works.
const path = require("path");

const SETTLE_MS = 1500;

module.exports.default = async ({ page }) => {
  page.on("load", () => {
    setTimeout(() => {
      const file = path.join(process.cwd(), `shot-${Date.now()}.jpg`);
      // A tab that closed or moved on before the shot leaves no file.
      page.screenshot({ path: file, type: "jpeg", quality: 60, timeout: 5000 }).catch(() => {});
    }, SETTLE_MS);
  });
};

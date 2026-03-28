#!/usr/bin/env node

const { execFileSync } = require("child_process");
const path = require("path");
const os = require("os");

const binName = os.platform() === "win32" ? "vibescan.exe" : "vibescan";
const binPath = path.join(__dirname, binName);

try {
  execFileSync(binPath, process.argv.slice(2), { stdio: "inherit" });
} catch (err) {
  if (err.status !== undefined) {
    process.exit(err.status);
  }
  console.error(
    "Failed to run vibescan. Try reinstalling: npm install -g @vibescan/cli"
  );
  process.exit(1);
}


const express = require("express");
const app = require("./app");

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Learn Orbit AI server is running on port ${PORT}`);
});

server.on("error", (error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Promise Rejection:", reason);
});

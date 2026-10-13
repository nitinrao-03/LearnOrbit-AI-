
const app = require("./app");

const PORT = Number(process.env.PORT || 3000);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Learn Orbit AI server running on port ${PORT}`);
});

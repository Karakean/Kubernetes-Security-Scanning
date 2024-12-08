const express = require("express");
const bodyParser = require("body-parser");
const { Client } = require("pg");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

const dbConfig = {
  user: process.env.DB_USER || "user",
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "database",
  password: process.env.DB_PASSWORD || "password",
  port: process.env.DB_PORT || 5432,
};

app.get("/", (req, res) => {
  res.send(`
    <form action="/login" method="POST">
      <label for="username">Username:</label>
      <input type="text" id="username" name="username" required>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const client = new Client(dbConfig);
    await client.connect();
    await client.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      username,
      password,
    ]);
    await client.end();
    res.send("Login successful!");
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).send("Internal Server Error");
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Web app running on port ${PORT}`);
});

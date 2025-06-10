require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const PORT = process.env.PORT || 5000;

const app = express();

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})

const express = require("express"),
    mongoose = require("mongoose"),
    bodyParser = require("body-parser"),
    cors = require("cors"),
    compression = require("compression"),
    app = express();
require("dotenv").config();

// Database Connectivity



var connectWithRetry = function () {
    return mongoose.connect(`${process.env.databaseURL}`
    );

};
connectWithRetry();

app.use(bodyParser.json({ limit: "50mb" }));
app.use(
    bodyParser.urlencoded({
        limit: "50mb",
        extended: true,
        parameterLimit: 50000,
    })
);
mongoose.Promise = global.Promise;
app.use(cors());
app.use(compression());

// API Routes

app.use("/", require("./routes/auth"));
// app.use("/contact", require("./routes/contact"));

// Server Listining

app.listen(`${process.env.PORT}`, () => {
    console.log("Listening on Port ", `${process.env.PORT}`);
});


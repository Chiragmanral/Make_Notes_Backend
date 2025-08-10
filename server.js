require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const randomUrl = require("random-url");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log("MongoDB Atlas connected"))
    .catch(err => console.log("Error in connecting with the MongoDB Atlas", err));

const notesSchema = mongoose.Schema({
    noteText: {
        type: String,
        required: true
    },
    notePassword: {
        type: String,
    },
    noteViewOnce: {
        type: Boolean,
    },
    noteViewAlways: {
        type: Boolean,
    },
    noteUrl: {
        type: String,
        required: true,
        unique: true
    },
    noteValidationTime: {
        type: Number,
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId, ref: "users"
    }
}, { timestamps: true });

const notes = mongoose.model("notes", notesSchema);

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    refreshToken: {
        type: String
    }
}, { timestamps: true });

const users = mongoose.model("users", userSchema);

setInterval(cleanExpiredNotes, 4 * 60 * 60 * 1000);

async function cleanExpiredNotes() {
    const currentTime = Date.now();

    try {
        const result = await notes.deleteMany({
            noteValidationTime: { $exists: true, $lt: currentTime },
            $and: [
                { $or: [{ noteViewOnce: { $ne: true } }, { noteViewOnce: { $exists: false } }] },
                { $or: [{ noteViewAlways: { $ne: true } }, { noteViewAlways: { $exists: false } }] }
            ]

        });

        if (result.deletedCount > 0) {
            console.log(`✅ Auto-cleanup: Deleted ${result.deletedCount} expired notes.`);
        } else {
            console.log("ℹ️ Auto-cleanup: No expired notes found.");
        }
    } catch (error) {
        console.error("❌ Auto-cleanup failed:", error);
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];

    if (!accessToken) {
        return res.status(401).json({ msg: "Token missing", loggedIn: false });
    }

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, decodedUser) => {
        if (err) {
            console.log("JWT verification failed:", err.message);

            let msg = "Invalid or expired token";
            if (err.name === 'TokenExpiredError') {
                msg = "Token expired";
            } else if (err.name === 'JsonWebTokenError') {
                msg = "Token malformed or invalid";
            }

            return res.status(403).json({ msg, loggedIn: false });
        }

        req.user = decodedUser; // contains payload like { id: user._id }
        next();
    });
}

function generateAccessToken(payload) {
    return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
}

function generateRefreshToken(payload) {
    return jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
}

app.post("/isTokensValid", (req, res) => {
    const { accessToken, refreshToken } = req.body;

    try {
        const decodedUserByAccessToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
        const decodedUserByRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);

        if (decodedUserByAccessToken && decodedUserByRefreshToken) {
            return res.json({ validTokens: true });
        }
        return res.json({ validTokens: false });
    }
    catch (err) {
        return res.json({ validTokens: false });
    }
})

app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    try {
        // if user already exists
        const existingUser = await users.findOne({ email });
        if (existingUser) return res.status(400).json({ success: false, msg: "Email already registered" });

        // if user already does not exists, create the user
        const hashedPassword = await bcrypt.hash(password, 10);
        await users.create({
            email,
            password: hashedPassword
        })
        res.json({ success: true });
    }
    catch (err) {
        console.error("There is some server issue!!", err);
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await users.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success: false });
        }

        const payload = { id: user._id };
        const accessToken = generateAccessToken(payload);
        const refreshToken = generateRefreshToken(payload);

        user.refreshToken = refreshToken;
        await user.save();
        return res.json({ success: true, accessToken: accessToken, refreshToken });
    }
    catch (err) {
        console.log("There is some server issue!!");
        return res.json({ success: false });
    }
})

app.post("/refresh-access-token", async (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) return res.json({ msg: "No refresh token provided" });
    try {
        const decodedUser = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await users.findById(decodedUser.id);
        if (!user || user.refreshToken !== refreshToken) {
            return res.status(403).json({ msg: "Invalid refresh token" });
        }

        const newAccessToken = generateAccessToken({ id: user._id });
        return res.json({ accessToken: newAccessToken });
    }
    catch (err) {
        return res.json({ msg: "Refresh token error" });
    }
})

app.post("/logout", async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ msg: "No token provided" });

    try {
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await users.findById(decoded.id);
        if (user) {
            user.refreshToken = null;
            await user.save();
        }
        res.json({ msg: "Logged out" });
    } catch (err) {
        res.status(400).json({ msg: "Logout failed" });
    }
});

app.post("/generateLink", authenticateToken, async (req, res) => {
    const body = req.body;
    const url = randomUrl("https");
    let hashedPassword = "";

    try {
        hashedPassword = body.notePassword ? await bcrypt.hash(body.notePassword, 10) : null;
    }
    catch (err) {
        return res.json({ msg: "Failed to secure note password" });
    }

    const payload = {
        noteText: body.noteText,
        notePassword: hashedPassword,
        noteUrl: url,
        createdBy: req.user.id
    };

    switch (body.noteDuration) {
        case "once":
            payload.noteViewOnce = true;
            break;
        case "always":
            payload.noteViewAlways = true;
            break;
        case "1hr":
            payload.noteValidationTime = Date.now() + 1 * 60 * 60 * 1000;
            break;
        case "8hr":
            payload.noteValidationTime = Date.now() + 8 * 60 * 60 * 1000;
            break;
        case "1day":
            payload.noteValidationTime = Date.now() + 24 * 60 * 60 * 1000;
            break;
    }

    await notes.create(payload);
    res.json({ generatedLink: url });
});

app.post("/getNote", authenticateToken, async (req, res) => {
    const { noteLinkCredential, passwordCredential } = req.body;

    try {
        const note = await notes.findOne({ noteUrl: noteLinkCredential });

        if (!note) {
            return res.json({ msg: "Either your credentials are wrong or the note has expired!!" });
        }

        // Password verification (if password was set)
        if (note.notePassword && !(await bcrypt.compare(passwordCredential, note.notePassword))) {
            return res.json({ msg: "Your credentials are wrong!!" });
        }

        const sendOnceAndDelete = async () => {
            const text = note.noteText;
            await notes.deleteOne({ noteUrl: noteLinkCredential });
            return res.json({ text });
        };

        if (note.noteViewOnce) {
            return await sendOnceAndDelete();
        }

        if (note.noteViewAlways) {
            return res.json({ text: note.noteText });
        }

        // Handle time-bound validation
        const currentTime = Date.now();
        if (currentTime <= note.noteValidationTime) {
            return res.json({ text: note.noteText });
        } else {
            await notes.deleteOne({ noteUrl: noteLinkCredential });
            return res.json({ msg: "Your note is expired!!, you can't access it now" });
        }
    }
    catch (err) {
        console.error("Error fetching note:", err);
        return res.json({ msg: "Internal server error" });
    }
});

app.get("/myNotes", authenticateToken, async (req, res) => {
    try {
        const userNotes = await notes.find({ createdBy: req.user.id });
        res.json({ notes: userNotes });
    }
    catch (err) {
        console.error("Error fetching user notes : ", err);
        res.json({ error: "Failed to fetch notes" });
    }
})

app.post("/viewMyNote", authenticateToken, async (req, res) => {
    const { noteUrl } = req.body;

    try {
        const note = await notes.findOne({ noteUrl, createdBy: req.user.id });

        if (!note) {
            return res.status(404).json({ msg: "Note not found or you are not the author" });
        }

        res.json({
            text: note.noteText,
            isPassword: note.notePassword ? "Password protected" : "No password"
        });
    }
    catch (err) {
        console.error("Error viewing note:", err);
        res.status(500).json({ msg: "Internal server error" });
    }
});

app.post("/deleteNote", authenticateToken, async (req, res) => {
    const { noteUrl } = req.body;

    try {
        const deleted = await notes.deleteOne({ noteUrl, createdBy: req.user.id }); // ensure author only
        if (deleted.deletedCount === 1) {
            return res.json({ deleted: true });
        }
        return res.json({ deleted: false });
    }
    catch (err) {
        console.log("Error failed to delete the note", err);
        return res.json({ deleted: false });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})

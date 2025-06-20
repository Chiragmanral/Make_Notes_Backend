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
app.use(express.urlencoded({ extended : false }));
app.use(express.json());

mongoose.connect(process.env.MONGO_URL)
  .then(() => console.log("MongoDB Atlas connected"))
  .catch(err => console.log("Error in connecting with the MongoDB Atlas", err));

const notesSchema = mongoose.Schema({
    noteText : {
        type : String,
        required : true
    },
    notePassword : {
        type : String,
    },
    noteViewOnce : {
        type : Boolean,
    },
    noteViewAlways : {
        type : Boolean,
    },
    noteUrl : {
        type : String,
        required : true,
        unique : true
    },
    noteValidationTime : {
        type: Number,
    },
    createdBy : {
        type : mongoose.Schema.Types.ObjectId, ref : "users"
    }
}, { timestamps : true }); 

const notes = mongoose.model("notes", notesSchema);

const userSchema = mongoose.Schema({
    email : {
        type : String,
        required : true,
        unique : true
    },
    password : {
        type : String,
        required : true
    }
}, { timestamps : true });

const users = mongoose.model("users", userSchema);

app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await users.create({
            email,
            password : hashedPassword
        })
        res.json({ success : true });
    }
    catch(err) {
        console.error("There is some server issue!!", err);
    }
});

// app.post("/login", async (req, res) => {
//     const { email, password } = req.body;
//     try {
//         const user = await users.findOne({ email });
//         if(!user || (await bcrypt.compare(password, user.password) === false)) {
//             res.json({ success : false });
//         }
//         res.json({ success : true })
//     }
//     catch(err) {
//         console.error("There is some server issue!!", err);
//     }
// })

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await users.findOne({ email });
        if(!user || !(await bcrypt.compare(password, user.password))) {
            return res.json({ success : false });
        }

        const payload = { id : user._id };
        const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET);
        return res.json({ success : true, token : accessToken });
    }
    catch(err) {
        console.error("There is some server issue!!", err);
        return res.status(500).json({ success : false, error : "Server error"});
    }
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if(!token) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, userId) => {
        if(err) return res.sendStatus(403);
        req.user = userId;
        next();
    })
}

setInterval(async () => {
  const currentTime = Date.now();
  try {
    const result = await notes.deleteMany({
      noteValidationTime: { $lt: currentTime },
      noteViewOnce: { $ne: true },
      noteViewAlways: { $ne: true },
    });
    if (result.deletedCount > 0) {
      console.log(`Auto-cleanup: Deleted ${result.deletedCount} expired notes.`);
    }
  } catch (error) {
    console.error("Auto-cleanup failed:", error);
  }
}, 12 * 60 * 60 * 1000);

app.post("/generateLink", authenticateToken, async (req, res) => {
    const body = req.body;
    const url = randomUrl("https");

    const payload = {
        noteText: body.noteText,
        notePassword: body.notePassword,
        noteUrl: url,
        createdBy : req.user.id
    };

    switch (body.noteDuration) {
    case "once":
        payload.noteViewOnce = true;
        break;
    case "always":
        payload.noteViewAlways = true;
        break;
    case "1hr":
        payload.noteValidationTime = Date.now() + 3600000;
        break;
    case "8hr":
        payload.noteValidationTime = Date.now() + 8 * 60 * 60 * 1000;
        break;
    case "1day":
        payload.noteValidationTime = Date.now() + 24 * 60 * 60 * 1000;
        break;
    }

    await notes.create(payload);
    res.json({ generatedLink : url});
});

app.post("/getNote", authenticateToken, async (req, res) => {
    const { noteLinkCredential, passwordCredential } = req.body;

    try {
        const note = await notes.findOne({ noteUrl: noteLinkCredential });

        if (!note) {
            return res.json({ msg: "Either your credentials are wrong or the note has expired!!" });
        }

        // Password verification (if password was set)
        if (note.notePassword && note.notePassword !== passwordCredential) {
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

app.get("myNotes", authenticateToken, async (req, res) => {
    try {
        const userNotes = await notes.find({ createdBy : req.user.id });
        res.json({ notes : userNotes });
    }
    catch(err) {
        console.error("Error fetching user notes : ", err);
        res.status(500).json({ error : "Failed to fetch notes"});
    }
})

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})

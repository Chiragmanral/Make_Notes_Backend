require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const randomUrl = require("random-url"); 
const cors = require("cors");
const app = express();
const PORT = 5000;

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
        required : true
    },
    noteValidationTime : {
        type: Number,
    }
}, { timestamps : true }); 

const notes = mongoose.model("notes", notesSchema);

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

app.post("/generateLink", async (req, res) => {
    const body = req.body;
    const url = randomUrl("https");

    const payload = {
        noteText: body.noteText,
        notePassword: body.notePassword,
        noteUrl: url
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

app.post("/getNote", async (req, res) => {
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


app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})

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

app.post("/generateLink", async (req, res) => {
    const body = req.body;
    const url = randomUrl("https");

    if(body.noteDuration === "once") {
        await notes.create({
        noteText : body.noteText,
        notePassword : body.notePassword,
        noteUrl : url,
        noteViewOnce : true
    })
    }

    else if(body.noteDuration === "always") {
        await notes.create({
        noteText : body.noteText,
        notePassword : body.notePassword,
        noteUrl : url,
        noteViewAlways : true
    })
    }

    else {
        if(body.noteDuration === "1hr") {
            await notes.create({
            noteText : body.noteText,
            notePassword : body.notePassword,
            noteUrl : url,
            noteValidationTime : Date.now() + 3600000
            })
        }

        else if(body.noteDuration === "1day") {
            await notes.create({
            noteText : body.noteText,
            notePassword : body.notePassword,
            noteUrl : url,
            noteValidationTime : Date.now() + 86400000
            })
        }

        else if(body.noteDuration === "1week") {
            await notes.create({
            noteText : body.noteText,
            notePassword : body.notePassword,
            noteUrl : url,
            noteValidationTime : Date.now() + 604800000
            })
        }

        else if(body.noteDuration === "1month") {
            await notes.create({
            noteText : body.noteText,
            notePassword : body.notePassword,
            noteUrl : url,
            noteValidationTime : Date.now() + 2629800000
            })
        }
    }
    res.json({ generatedLink : url});
})

app.post("/getNote", async (req, res) => {
    const body = req.body;
    const note = await notes.findOne({ noteUrl : body.noteLinkCredential });

    if(note.notePassword) {
        if(note.notePassword === body.passwordCredential) {
            if(note.noteDuration === "once") {
                res.json({ text : note.noteText});
            }
        }
    }
})

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
})

import express from 'express';
import fetchUser from '../middleware/fetchUser.js';
import Notes from '../models/Notes.js';
const router = express.Router();

//* ROUTE 1: Get All the Notes using: GET "/api/notes/fetchallnotes". Login required
router.get('/fetchallnotes', fetchUser, async (req, res) => {
    try {
        const notes = await Notes.find({ user: req.userId });
        res.json(notes);
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
})

//* ROUTE 2: Add new Note using: POST "/api/notes/addnote". Login required
router.post('/addnote', fetchUser, async (req, res) => {
    try {
        //* data comimg from body(frontend)
        const { title, description, tag } = req.body

        //* validation 
        if (!title || !description || !tag) {
            return res.status(400).json({ error: "All fields are required" });
        }

        //* Notes
        const notes = new Notes({ title, description, tag, user: req.userId });

        //* saving notes
        const savedNote = await notes.save();
        res.json(savedNote);

    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
})

export default router
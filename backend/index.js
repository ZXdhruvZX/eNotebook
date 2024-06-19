import connectToMongo from './database/db.js';
import express from 'express';
import auth from './routes/auth.js';
import notes from './routes/notes.js';
    
connectToMongo();
const app = express()
const port = 4000

//* middleware
app.use(express.json())
    
//* Available routes
app.use('/api/auth', auth)
app.use('/api/notes', notes)
    
app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
})
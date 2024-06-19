import 'dotenv/config';
import jwt from 'jsonwebtoken';

const fetchUser = (req, res, next) => {
    // Get the token from the header
    const token = req.header('auth-token');

    if (!token) {
        return res.status(401).send({ error: 'Please authenticate using a valid token' });
    }

    try {
        // Verify the token and extract userId
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId; // Assuming the token contains { userId: ... }
        console.log('fetchUser:', req.userId);
        next();
    } catch (error) {
        console.error(error);
        res.status(401).send({ error: 'Please authenticate using a valid token' });
    }
};

export default fetchUser;

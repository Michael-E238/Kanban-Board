import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const secretKey = process.env.SECRET_KEY as string;

export const login = async (req: Request, res: Response) => {
  try {
    // Get the username and password from the request body
    const { username, password } = req.body;

    // Find the user by username
    const user = await User.findOne({ where: { username } });

    // If the user doesn't exist, return an error
    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the provided password with the stored password
    const isValidPassword = await bcrypt.compare(password, user.password);

    // If the password is incorrect, return an error
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ username: user.username }, secretKey, { expiresIn: '1h' });

    // Return the JWT token
    return res.json({ token });
  } catch (error) {
    // If an error occurs, return an error message
    return res.status(500).json({ message: 'An error occurred' });
  }
};

const router = Router();

// POST /login - Login a user
router.post('/login', login);

export default router;
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface JwtPayload {
  username: string;
}

const secretKey = process.env.SECRET_KEY as string;

export const authenticateToken = (req: Request, res: Response, next: NextFunction) => {
  // Get the token from the headers
  const token = req.header('Authorization');

  // Check if the token exists
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  // Verify the token
  try {
    const decoded = jwt.verify(token, secretKey) as JwtPayload;
    req.user = decoded;
    return next(); // Call next and return
  } catch (error) {
    return res.status(400).json({ message: 'Invalid token.' });
  }
};
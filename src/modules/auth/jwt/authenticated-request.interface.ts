import { Request } from 'express';

export interface AuthenticatedUser {
  userId: string;
  email: string;
}

export interface AuthenticatedRequest extends Request {
  user: AuthenticatedUser;
}

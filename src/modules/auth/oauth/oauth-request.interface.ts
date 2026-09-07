import { Request } from 'express';
import { OauthUser } from './oauth-user.interface';

export interface OauthRequest extends Request {
  user: OauthUser;
}

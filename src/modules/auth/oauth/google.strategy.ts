import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { OauthUser } from './oauth-user.interface';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.getOrThrow<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.getOrThrow<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow<string>('GOOGLE_CALLBACK_URL'),
      scope: ['email', 'profile'],
    });
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ) {
    const primaryEmail = profile.emails?.[0]?.value;

    if (!primaryEmail) {
      done(new Error('No primary email found for Google user'), undefined);
      return;
    }

    const user: OauthUser = {
      providerId: profile.id,
      email: primaryEmail,
      displayName: profile.displayName,
    };
    done(null, user);
  }
}

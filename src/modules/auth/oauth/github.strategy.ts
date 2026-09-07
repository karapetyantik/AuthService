import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ConfigService } from '@nestjs/config';
import { Strategy, Profile } from 'passport-github2';
import { OauthUser } from './oauth-user.interface';

type GitHubDone = (err: Error | null, user?: OauthUser) => void;

@Injectable()
export class GitHubStrategy extends PassportStrategy(Strategy, 'github') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.getOrThrow<string>('GITHUB_CLIENT_ID'),
      clientSecret: configService.getOrThrow<string>('GITHUB_CLIENT_SECRET'),
      callbackURL: configService.getOrThrow<string>('GITHUB_CALLBACK_URL'),
      scope: ['user:email'],
    });
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: GitHubDone,
  ) {
    const primaryEmail = profile.emails?.[0]?.value;

    if (!primaryEmail) {
      done(new Error('No primary email found for GitHub user'));
      return;
    }

    const user: OauthUser = {
      providerId: profile.id,
      email: primaryEmail,
      displayName: profile.username ?? profile.displayName,
    };
    done(null, user);
  }
}

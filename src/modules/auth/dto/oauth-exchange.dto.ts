import { IsString, Length } from 'class-validator';

export class OauthExchangeDto {
  @IsString()
  @Length(1, 128)
  code!: string;
}

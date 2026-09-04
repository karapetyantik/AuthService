import { IsString, Matches } from 'class-validator';

export class TotpLoginDto {
  @IsString()
  tempToken!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'Код должен состоять из 6 цифр' })
  code!: string;
}

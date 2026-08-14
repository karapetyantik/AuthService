import { IsEmail, IsString, Matches } from 'class-validator';

export class VerifyEmailCodeDto {
  @IsEmail()
  email!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'Код должен состоять ровно из 6 цифр' })
  code!: string;
}

import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

type MailOptions = {
  subject: string;
  email: string;
  name: string;
  activationCode: string;
  template: string;
};

@Injectable()
export class EmailService {
  constructor(private mailerService: MailerService) {}
  async sendMail({
    subject,
    email,
    name,
    activationCode,
    template,
  }: MailOptions) {
    await this.mailerService.sendMail({
      to: email,
      subject,
      template,
      context: {
        name,
        activationCode,
      },
    });
  }
}

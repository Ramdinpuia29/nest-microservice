import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { ActivationDto, LoginDto, RegisterDto } from './dto/user.dto';
import { PrismaService } from '../../../prisma/prisma.service';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';
import { EmailService } from './email/email.service';

interface UserData {
  name: string;
  email: string;
  password: string;
  phoneNumber: number;
}

@Injectable()
export class UsersService {
  constructor(
    private jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
  ) {}

  async register(registerDto: RegisterDto, response: Response) {
    const { name, email, phoneNumber, password } = registerDto;

    const isEmailTaken = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (isEmailTaken) {
      throw new BadRequestException(
        'Someone already registered using this email',
      );
    }

    const isPhoneNumberTaken = await this.prisma.user.findUnique({
      where: {
        phoneNumber,
      },
    });

    if (isPhoneNumberTaken) {
      throw new BadRequestException(
        'Someone already registered using this phone number',
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      name,
      email,
      phoneNumber,
      password: hashedPassword,
    };

    const activationToken = await this.createActivationToken(user);

    const activationCode = activationToken.activationCode;

    const activation_token = activationToken.token;

    await this.emailService.sendMail({
      email,
      subject: 'Activate your account',
      template: './activation-mail',
      name,
      activationCode,
    });

    return { activation_token, response };
  }

  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

    const token = this.jwtService.sign(
      { user, activationCode },
      {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
        expiresIn: '5m',
      },
    );

    return { token, activationCode };
  }

  async activateUser(activationDto: ActivationDto, response: Response) {
    const { activationToken, activationCode } = activationDto;

    const newUser: { user: UserData; activationCode: string } =
      this.jwtService.verify(activationToken, {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
      });

    if (newUser.activationCode !== activationCode) {
      throw new BadRequestException('Invalid activation code');
    }

    const { name, email, password, phoneNumber } = newUser.user;

    const isEmailTaken = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (isEmailTaken) {
      throw new BadRequestException(
        'Someone already registered using this email',
      );
    }

    const isPhoneNumberTaken = await this.prisma.user.findUnique({
      where: {
        phoneNumber,
      },
    });

    if (isPhoneNumberTaken) {
      throw new BadRequestException(
        'Someone already registered using this phone number',
      );
    }

    const user = await this.prisma.user.create({
      data: {
        name,
        email,
        password,
        phoneNumber,
      },
    });

    return { user, response };
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    const user = {
      email,
      password,
    };
    return user;
  }

  async getUsers() {
    const users = await this.prisma.user.findMany();
    return users;
  }
}

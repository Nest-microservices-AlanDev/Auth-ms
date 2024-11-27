import {
  Injectable,
  Logger,
  NotFoundException,
  OnModuleInit,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginUserDto, RegisterUserDto } from './dto';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthDB');

  constructor(private jwtService: JwtService) {
    super();
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Mongo connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    try {
      const { name, email, password } = registerUserDto;
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User alredy exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10), //? encriptar contraseña
          name,
        },
      });

      const { password: ___, ...rest } = newUser;

      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: error.status || 500,
        message: error.message,
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    try {
      const { email, password } = loginUserDto;
      const user = await this.user.findUnique({
        where: {
          email,
        },
      });
      if (!user) {
        throw new NotFoundException('User not found');
      }

      const { password: userPassword, ...rest } = user;
      if (!bcrypt.compareSync(password, userPassword)) {
        throw new UnauthorizedException('Invalid credentials');
      }
      return {
        user: rest,
        token: await this.signJwt(rest),
      };
    } catch (error) {
      throw new RpcException({
        status: error.status || 500,
        message: error.message,
      });
    }
  }

  async validateToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.JWT_SECRET,
      });
      return {
        user: user,
        token: await this.signJwt(user),
      };
    } catch (error) {
      throw new RpcException({
        status: 401,
        message: 'not valid token',
      });
    }
  }
}

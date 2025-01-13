import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async register(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return this.prisma.user.create({ data: { email, password: hashedPassword } });
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw new Error('Invalid credentials');
    }
    return { token: this.jwtService.sign({ userId: user.id }) };
  }

  async forgotPassword(email: string) {
    const token = Math.random().toString(36).substring(2);
    const tokenExp = new Date(Date.now() + 3600000); // 1 hour expiry
    await this.prisma.user.update({
      where: { email },
      data: { resetToken: token, resetTokenExp: tokenExp },
    });
    return token;
  }

  async resetPassword(token: string, newPassword: string) {
    const user = await this.prisma.user.findFirst({ where: { resetToken: token } });
    if (!user || user.resetTokenExp < new Date()) throw new Error('Token expired');

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    return this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, resetToken: null, resetTokenExp: null },
    });
  }
}

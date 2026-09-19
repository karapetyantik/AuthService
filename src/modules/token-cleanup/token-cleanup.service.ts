import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '@common/prisma/prisma.service';

const REVOKED_TOKEN_RETENTION_DAYS = 30;

@Injectable()
export class TokenCleanupService {
  private readonly logger = new Logger(TokenCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async purgeRevokedTokens(): Promise<void> {
    const cutoff = new Date(
      Date.now() - REVOKED_TOKEN_RETENTION_DAYS * 24 * 60 * 60 * 1000,
    );

    const { count } = await this.prisma.refreshToken.deleteMany({
      where: { revokedAt: { not: null, lt: cutoff } },
    });

    if (count > 0) {
      this.logger.log(`Удалено отозванных refresh-токенов: ${count}`);
    }
  }
}

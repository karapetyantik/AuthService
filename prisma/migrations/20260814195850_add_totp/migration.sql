-- AlterTable
ALTER TABLE "User" ADD COLUMN     "isTotpEnabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "totpSecret" TEXT;

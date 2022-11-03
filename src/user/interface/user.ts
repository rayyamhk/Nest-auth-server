export enum ROLE {
  ADMIN = 'admin',
  USER = 'user',
}

export interface User {
  id: string;
  email: string;
  hashedPassword: string;
  salt: string;
  role: ROLE;
  createdAt: number;
  hashedRefreshToken?: string;
}

export interface PublicUser {
  id: string;
  email: string;
  role: ROLE;
  createdAt: number;
}

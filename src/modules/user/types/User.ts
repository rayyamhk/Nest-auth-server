type Role = 'user' | 'admin';

export type User = {
  id: string;
  email: string;
  hashedPassword: string;
  salt: string;
  role: Role;
  createdAt: string;
  refreshTokens: {
    [identifier: string]: string;
  };
};

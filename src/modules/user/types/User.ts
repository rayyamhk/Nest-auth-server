type Role = 'user' | 'admin';

export type User = {
  _id: string;
  email: string;
  hashedPassword: string;
  salt: string;
  role: Role;
  createdAt: string;
  refreshTokens: {
    [sessionId: string]: string;
  };
};

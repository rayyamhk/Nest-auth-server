// Mongo Collection Name
export const USER_COLLECTION = 'users';

export const COLLECTION_NAME = Symbol('COLLECTION_NAME');

// Regex
export const EMAIL_REGEX =
  /^[a-z0-9!#$%&'*+-/=?^_`{|}~]+(?:\.[a-z0-9!#$%&'*+-/=?^_`{|}~])*@[a-z0-9][-a-z0-9]*(?:\.[-a-z0-9]+)*\.[-a-z0-9]*[a-z0-9]$/i;
export const USERNAME_REGEX = /^(?!.*\.\.)(?!.*\.$)[^\W][\w.]{0,15}$/;
export const STRONG_PASSWORD_REGEX = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/;

// Cookie
export const COOKIE_REFRESH_TOKEN = 'aniflex_refresh_token';
export const COOKIE_SESSION_ID = 'aniflex_session_id';

// JWT
export const JWT_ACCESS_TOKEN_EXP = 1000 * 60 * 10; // 10m
export const JWT_REFRESH_TOKEN_EXP = 1000 * 60 * 60 * 24 * 7; // 7d

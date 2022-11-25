// Database Name
export const USER_TABLE = 'Users';

export const TABLE_NAME = Symbol('TABLE_NAME');

// Regex
export const EMAIL_REGEX =
  /^[a-z0-9!#$%&'*+-/=?^_`{|}~]+(?:\.[a-z0-9!#$%&'*+-/=?^_`{|}~])*@[a-z0-9][-a-z0-9]*(?:\.[-a-z0-9]+)*\.[-a-z0-9]*[a-z0-9]$/i;
export const USERNAME_REGEX = /^(?!.*\.\.)(?!.*\.$)[^\W][\w.]{0,15}$/;
export const STRONG_PASSWORD_REGEX = /(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])/;

# Auth Service
An authentication and authorization service powered by **NestJS** and **Amazon DynamoDB**.

## APIs
#### Sign-up:

##### End-point
POST /signup

##### Request Body
| Field | Description |
| ------------ | ------------ |
| email | A valid email that doesn't exist in the database |
| password | A strong password (at least 8 characters, containing at least one uppercase, one lowercase, and one digit) |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 201  | Created a new user successfully  |
| 400  | Invalid email and password  |
| 409  | Email already existed  |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/signout'
	--header 'Content-Type: application/json'
	--header 'X-API-KEY: YOUR_API_KEY'
	--data-raw '{
		"email": YOUR_EMAIL,
		"password": YOUR_PASSWORD
	}'
```

#### Sign-in
Authenticate a user and return a pair of JWT access token and refresh token.

##### End-point
POST /signin

#### Request Header
| Field | Description |
| ------------ | ------------ |
| x-agent-identifier | A key represents the sign-in device, used to support multi-device login |

##### Request Body
| Field | Description |
| ------------ | ------------ |
| email | User email address |
| password | User password |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Authenticate successfully  |
| 401  | Email doesn't exist, or incorrect password |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/signin'
	--header 'Content-Type: application/json'
	--header 'X-API-KEY: YOUR_API_KEY'
	--header 'X-AGENT-IDENTIFIER: IDENTIFIER'
	--data-raw '{
		"email": YOUR_EMAIL,
		"password": YOUR_PASSWORD
	}'
```

#### Sign-out

##### End-point
POST /signout

##### Request Header
| Field | Description |
| ------------ | ------------ |
| x-agent-identifier | A key represents the sign-in device, used to support multi-device login |

##### Request Body
| Field | Description |
| ------------ | ------------ |
| refreshToken | The refresh token will be revoked in the database |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Sign-out successfully  |
| 400  | Missing request header, or invalid JWT access token |
| 403  | Token expired, or token reused (refresh token rotation error) |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/signout'
	--header 'Content-Type: application/json'
	--header 'X-AGENT-IDENTIFIER: IDENTIFIER'
	--header 'X-API-KEY: YOUR_API_KEY'
	--data-raw '{
		refreshToken: YOUR_REFRESH_TOKEN
	}'
```

#### Authorize JWT Access Token
Authorize a user, return an user object.

##### End-point
POST /authorize

##### Request Header
| Field | Description |
| ------------ | ------------ |
| Authorization | Valid JWT Access Token |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Authorize successfully  |
| 403  | Missing request header, or invalid JWT access token |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/authorize'
	--header 'Authorization: Bearer YOUR_JWT_TOKEN'
	--header 'X-API-KEY: YOUR_API_KEY'
```

#### Refresh JWT Access Token
Refresh an access token by providing a valid refresh token. Return a pair of new access token and refresh token, and the old refresh token will be revoked (Refresh Token Rotation).

##### End-point
POST /refresh

##### Request Header
| Field | Description |
| ------------ | ------------ |
| x-agent-identifier | A key represents the sign-in device, used to support multi-device login |

##### Request Body
| Field | Description |
| ------------ | ------------ |
| refreshToken | The refresh token will be revoked in the database |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Refresh successfully  |
| 400  | Missing request header |
| 403  | Invalid refresh token, or token reused |
| 409  | User already signed out  |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/refresh'
	--header 'Content-Type: application/json'
	--header 'X-AGENT-IDENTIFIER: IDENTIFIER'
	--header 'X-API-KEY: YOUR_API_KEY'
	--data-raw '{
		refreshToken: YOUR_REFRESH_TOKEN
	}'
```
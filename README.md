# Auth Service
An authentication and authorization service powered by **NestJS** and **Amazon DynamoDB**.

## APIs
#### Sign-up:

##### End-point
POST /auth/signup

##### Request Body
| Field | Description | Required |
| ------------ | ------------ |
| email | A valid email that doesn't exist in the database | True |
| password | A strong password (at least 8 characters, containing at least one uppercase, one lowercase, and one digit) | True |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 201  | Created a new user successfully  |
| 400  | Invalid email, invalid password, or email already exists  |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/auth/signout'
	--header 'Content-Type: application/x-www-form-urlencoded'
	--header 'X-API-KEY: YOUR_API_KEY'
	--data-urlencode 'email=YOUR_EMAIL'
	--data-urlencode 'password=YOUR_PASSWORD'
```

#### Sign-in
Authenticate a user and return a pair of JWT access token and refresh token.

##### End-point
POST /auth/signin

##### Request Body
| Field | Description | Required |
| ------------ | ------------ |
| email | User email address | True |
| password | User password | True |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Authenticate successfully  |
| 400  | Missing email or password |
| 401  | Email doesn't exist, or incorrect password |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/auth/signin'
	--header 'Content-Type: application/x-www-form-urlencoded'
	--header 'X-API-KEY: YOUR_API_KEY'
	--data-urlencode 'email=YOUR_EMAIL'
	--data-urlencode 'password=YOUR_PASSWORD'
```

#### Sign-out

##### End-point
POST /auth/signout

##### Request Header
| Field | Description | Required |
| ------------ | ------------ |
| Authorization | Valid JWT Access Token | True |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Sign-out successfully  |
| 400  | Missing request header, or invalid JWT access token |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/auth/signout'
	--header 'Authorization: Bearer YOUR_JWT_TOKEN'
	--header 'X-API-KEY: YOUR_API_KEY'
```

#### Authorize JWT Access Token
Authorize a user, return an user object.

##### End-point
POST /auth/authorize

##### Request Header
| Field | Description | Required |
| ------------ | ------------ |
| Authorization | Valid JWT Access Token | True |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Authorize successfully  |
| 403  | Missing request header, or invalid JWT access token |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/auth/authorize'
	--header 'Authorization: Bearer YOUR_JWT_TOKEN'
	--header 'X-API-KEY: YOUR_API_KEY'
```

#### Refresh JWT Access Token
Refresh an access token by providing a valid refresh token. Return a pair of new access token and refresh token. The old refresh token becomes invalid (Refresh Token Rotation).

##### End-point
POST /auth/refresh

##### Request Header
| Field | Description | Required |
| ------------ | ------------ |
| Authorization | Valid JWT Refresh Token | True |

##### Response
| Code  | Description  |
| ------------ | ------------ |
| 200  | Refresh successfully  |
| 400  | Missing request header, refresh token reused, or invalid refresh token |
| 500  | Server errors  |

##### Example
```
curl
	--request POST YOUR_URL/auth/refresh'
	--header 'Authorization: Bearer YOUR_JWT_TOKEN'
	--header 'X-API-KEY: YOUR_API_KEY'
```
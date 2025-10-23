# Auth0 + Rails + Next.js Authentication Demo

Simple authentication implementation using Auth0, Rails API, and Next.js frontend.

## 🚀 Features

- **Auth0 Authentication**: Login/logout functionality
- **JWT Token Validation**: Rails API validates Auth0 JWT tokens
- **Protected Routes**: Dashboard page requires authentication
- **Public & Private Endpoints**: Test both authenticated and unauthenticated API calls
- **Modern Stack**: Next.js 16 (App Router) + Rails 8 + Tailwind CSS

## 📋 Prerequisites

- Node.js 18+ (with npm)
- Ruby 3.2+
- Rails 8+
- Auth0 Account

## 🔧 Setup

### 1. Auth0 Configuration

1. Create an Auth0 account at [auth0.com](https://auth0.com)
2. Create a new **Application** (Regular Web Application)
3. Create a new **API**
4. Note down:
   - Domain (e.g., `your-tenant.auth0.com`)
   - Client ID
   - Client Secret
   - API Identifier

### 2. Backend Setup (Rails)

```bash
cd backend

# Install dependencies
bundle install

# Create .env file
cp .env.example .env

# Edit .env with your Auth0 credentials
# AUTH0_DOMAIN=https://your-tenant.auth0.com
# AUTH0_API_IDENTIFIER=your_api_identifier
# FRONTEND_URL=http://localhost:3000

# Start Rails server (port 3001)
rails server -p 3001
```

### 3. Frontend Setup (Next.js)

```bash
cd frontend

# Install dependencies
npm install

# Create .env.local file
cp .env.local.example .env.local

# Edit .env.local with your Auth0 credentials
# AUTH0_DOMAIN=your-tenant.auth0.com
# AUTH0_CLIENT_ID=your_client_id
# AUTH0_CLIENT_SECRET=your_client_secret
# AUTH0_BASE_URL=http://localhost:3000

# Start Next.js dev server
npm run dev
```

### 4. Auth0 Application Settings

In your Auth0 Application settings, configure:

**Allowed Callback URLs:**
```
http://localhost:3000/api/auth/callback
```

**Allowed Logout URLs:**
```
http://localhost:3000
```

**Allowed Web Origins:**
```
http://localhost:3000
```

## 🎮 Usage

1. Open http://localhost:3000 in your browser
2. Click "Login with Auth0"
3. Complete Auth0 authentication
4. You'll be redirected to the home page (logged in)
5. Click "Go to Dashboard" to access protected content
6. Test the Rails API endpoints:
   - **Public API**: No authentication required
   - **Private API**: Requires JWT token from Auth0

## 📁 Project Structure

```
next-rails-auth0/
├── backend/                 # Rails API
│   ├── app/
│   │   ├── controllers/
│   │   │   ├── api/v1/
│   │   │   │   ├── public_controller.rb
│   │   │   │   └── private_controller.rb
│   │   │   └── concerns/
│   │   │       └── secured.rb
│   │   └── lib/
│   │       └── json_web_token.rb
│   └── config/
│       └── initializers/
│           └── cors.rb
└── frontend/                # Next.js App
    ├── src/
    │   └── app/
    │       ├── api/auth/[auth0]/
    │       │   └── route.ts
    │       ├── dashboard/
    │       │   └── page.tsx
    │       └── page.tsx
    └── .env.local.example
```

## 🔐 How It Works

### Authentication Flow

1. User clicks "Login" → Redirects to Auth0
2. User authenticates with Auth0
3. Auth0 redirects back with authorization code
4. Frontend exchanges code for tokens (access_token, id_token)
5. Tokens stored in HTTP-only cookie
6. Frontend includes access_token in API requests
7. Rails validates JWT token using Auth0's public key

### API Authentication

**Frontend → Rails:**
```typescript
fetch('http://localhost:3001/api/v1/private', {
  headers: {
    Authorization: `Bearer ${accessToken}`
  }
})
```

**Rails JWT Validation:**
```ruby
# Validates token signature using Auth0 JWKS
# Verifies issuer (iss) and audience (aud)
JsonWebToken.verify(token)
```

## 🛠️ Technologies

- **Frontend**: Next.js 16, React 19, TypeScript, Tailwind CSS
- **Backend**: Rails 8, Ruby 3.2+
- **Authentication**: Auth0, JWT
- **Package Manager**: npm (frontend), Bundler (backend)

## 📝 API Endpoints

### Frontend (Next.js)
- `GET /api/auth/login` - Initiate Auth0 login
- `GET /api/auth/callback` - Auth0 callback handler
- `GET /api/auth/logout` - Logout and clear session
- `GET /api/auth/me` - Get current user info

### Backend (Rails)
- `GET /api/v1/public` - Public endpoint (no auth required)
- `GET /api/v1/private` - Protected endpoint (requires JWT)

## 🐛 Troubleshooting

### CORS Errors
Ensure `FRONTEND_URL` in backend `.env` matches your frontend URL.

### Auth0 Errors
- Verify callback URLs are configured in Auth0 dashboard
- Check domain format (should include `https://`)
- Ensure API identifier matches

### JWT Validation Fails
- Confirm `AUTH0_DOMAIN` and `AUTH0_API_IDENTIFIER` in backend
- Check token is being sent in `Authorization` header
- Verify API audience in Auth0 dashboard

## 📄 License

MIT

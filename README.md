# Auth0 + Rails + Next.js Authentication Demo

Auth0を使用した認証システムの実装例。Rails APIバックエンドとNext.jsフロントエンドで構成されています。

## 🚀 Features

- **Auth0 Authentication**: ログイン/ログアウト機能
- **JWT Token Validation**: Rails APIがAuth0 JWTトークンを検証
- **Protected Routes**: 認証が必要なダッシュボードページ
- **Public & Private Endpoints**: 認証の有無で使い分けるAPIエンドポイント
- **Modern Stack**: Next.js 16 (App Router) + Rails 8 + Tailwind CSS

## 📋 Prerequisites

- Node.js 18+ (with npm)
- Ruby 3.2+
- Rails 8+
- Auth0 Account (無料アカウントで可)

## 🎯 プロジェクト作成からデプロイまでの完全ガイド

### Phase 1: Auth0の設定

#### 1.1 Auth0アカウント作成
1. [auth0.com](https://auth0.com) にアクセスして「Sign Up」
2. テナント名を決定（例: `dev-myapp`）→ `dev-myapp.auth0.com` になります
3. リージョンを選択（日本なら `Asia Pacific (Sydney)` が最も近い）

#### 1.2 Application（アプリケーション）の作成
1. Auth0ダッシュボード → **Applications** → **Create Application**
2. 名前: `Next.js Frontend`
3. タイプ: **Regular Web Applications** を選択
4. **Settings** タブで以下を設定:

**必須項目:**
```
Allowed Callback URLs:
http://localhost:3000/api/auth/callback

Allowed Logout URLs:
http://localhost:3000

Allowed Web Origins:
http://localhost:3000

Allowed Origins (CORS):
http://localhost:3000
```

5. **Save Changes** をクリック
6. 以下の情報をメモ:
   - Domain: `your-tenant.auth0.com`
   - Client ID
   - Client Secret（「Show」をクリックして表示）

#### 1.3 API の作成
1. Auth0ダッシュボード → **Applications** → **APIs** → **Create API**
2. 設定:
   - Name: `Rails API`
   - Identifier: `https://my-rails-api` (任意のURL形式、実在する必要なし)
   - Signing Algorithm: `RS256` (デフォルト)
3. **Create** をクリック
4. **Identifier** をメモ（環境変数で使用）

### Phase 2: Railsバックエンドのセットアップ

#### 2.1 Railsプロジェクト作成（既存の場合はスキップ）
```bash
# Railsプロジェクトが既にある場合は不要
rails new backend --api --database=sqlite3
cd backend
```

#### 2.2 必要なGemを追加
`Gemfile` に以下を追加:
```ruby
# Use JWT for Auth0 token verification
gem "jwt"

# Load environment variables from .env file
gem "dotenv-rails", groups: [:development, :test]

# Use Rack CORS for handling Cross-Origin Resource Sharing (CORS)
gem "rack-cors"
```

#### 2.3 Gemをインストール
```bash
bundle install
```

#### 2.4 CORS設定
`config/initializers/cors.rb` を作成:
```ruby
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins ENV['FRONTEND_URL'] || 'http://localhost:3000'

    resource "*",
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head],
      credentials: true
  end
end
```

#### 2.5 JWT検証ライブラリを作成
`app/lib/json_web_token.rb`:
```ruby
require 'net/http'
require 'uri'

class JsonWebToken
  def self.verify(token)
    auth0_issuer = normalize_domain(ENV['AUTH0_DOMAIN'])
    
    # Auth0 tokens have trailing slash in issuer, so we need to accept both
    JWT.decode(token, nil,
              true,
              algorithms: 'RS256',
              iss: [auth0_issuer, "#{auth0_issuer}/"],
              verify_iss: true,
              aud: ENV['AUTH0_API_IDENTIFIER'],
              verify_aud: true) do |header|
      jwks_hash[header['kid']]
    end
  end

  def self.jwks_hash
    jwks_url = "#{normalize_domain(ENV['AUTH0_DOMAIN'])}/.well-known/jwks.json"
    uri = URI(jwks_url)
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = Rails.env.production? ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Get.new(uri.request_uri)
    response = http.request(request)
    
    jwks_raw = response.body
    jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
    Hash[
      jwks_keys.map do |k|
        [
          k['kid'],
          OpenSSL::X509::Certificate.new(
            Base64.decode64(k['x5c'].first)
          ).public_key
        ]
      end
    ]
  end

  private

  def self.normalize_domain(domain)
    return nil if domain.nil? || domain.empty?
    domain = "https://#{domain}" unless domain.start_with?('http://', 'https://')
    domain.chomp('/')
  end
end
```

#### 2.6 認証Concernを作成
`app/controllers/concerns/secured.rb`:
```ruby
module Secured
  extend ActiveSupport::Concern

  included do
    before_action :authenticate_request!
  end

  private

  def authenticate_request!
    auth_token
  rescue JWT::VerificationError, JWT::DecodeError => e
    Rails.logger.error "JWT Verification failed: #{e.message}"
    render json: { errors: ['Not Authenticated'] }, status: :unauthorized
  end

  def http_token
    if request.headers['Authorization'].present?
      request.headers['Authorization'].split(' ').last
    end
  end

  def auth_token
    JsonWebToken.verify(http_token)
  end
end
```

#### 2.7 コントローラーを作成
```bash
# Public APIコントローラー
mkdir -p app/controllers/api/v1
```

`app/controllers/api/v1/public_controller.rb`:
```ruby
class Api::V1::PublicController < ApplicationController
  def index
    render json: { message: "Hello from a public endpoint! You don't need to be authenticated to see this." }
  end
end
```

`app/controllers/api/v1/private_controller.rb`:
```ruby
class Api::V1::PrivateController < ApplicationController
  include Secured

  def index
    render json: { message: 'Hello from a private endpoint! You need to be authenticated to see this.' }
  end
end
```

#### 2.8 ルーティング設定
`config/routes.rb`:
```ruby
Rails.application.routes.draw do
  get "up" => "rails/health#show", as: :rails_health_check

  namespace :api do
    namespace :v1 do
      get 'private' => 'private#index'
      get 'public' => 'public#index'
    end
  end
end
```

#### 2.9 環境変数設定
`.env` ファイルを作成:
```bash
# Auth0 settings (domain without https://)
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_API_IDENTIFIER=https://my-rails-api

# Frontend URL
FRONTEND_URL=http://localhost:3000
```

#### 2.10 データベース準備
```bash
bin/rails db:create
bin/rails db:prepare
```

#### 2.11 Railsサーバー起動
```bash
bundle exec rails server -p 3001
```

### Phase 3: Next.jsフロントエンドのセットアップ

#### 3.1 Next.jsプロジェクト作成
```bash
cd ..
npx create-next-app@latest frontend --typescript --tailwind --app --use-npm
cd frontend
```

#### 3.2 Auth0パッケージをインストール
```bash
npm install @auth0/nextjs-auth0 --legacy-peer-deps
```

#### 3.3 環境変数設定
`.env.local` ファイルを作成:
```bash
# Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_BASE_URL=http://localhost:3000
AUTH0_AUDIENCE=https://my-rails-api

# Backend API URL
NEXT_PUBLIC_API_URL=http://localhost:3001
```

#### 3.4 Auth0 APIルートを作成
`src/app/api/auth/[auth0]/route.ts`:
```typescript
import { NextRequest, NextResponse } from 'next/server';

const auth0Domain = process.env.AUTH0_DOMAIN!;
const auth0ClientId = process.env.AUTH0_CLIENT_ID!;
const auth0ClientSecret = process.env.AUTH0_CLIENT_SECRET!;
const auth0Audience = process.env.AUTH0_AUDIENCE || process.env.NEXT_PUBLIC_AUTH0_AUDIENCE;
const baseUrl = process.env.AUTH0_BASE_URL || 'http://localhost:3000';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ auth0: string }> }
) {
  const { auth0 } = await params;

  if (auth0 === 'login') {
    const redirectUri = `${baseUrl}/api/auth/callback`;
    const authUrl = `https://${auth0Domain}/authorize?` +
      `response_type=code&` +
      `client_id=${auth0ClientId}&` +
      `redirect_uri=${encodeURIComponent(redirectUri)}&` +
      `scope=openid profile email&` +
      `audience=${encodeURIComponent(auth0Audience || '')}`;
    
    return NextResponse.redirect(authUrl);
  }

  if (auth0 === 'logout') {
    const logoutUrl = `https://${auth0Domain}/v2/logout?` +
      `client_id=${auth0ClientId}&` +
      `returnTo=${encodeURIComponent(baseUrl)}`;
    
    const response = NextResponse.redirect(logoutUrl);
    response.cookies.delete('auth0_session');
    
    return response;
  }

  if (auth0 === 'callback') {
    const code = request.nextUrl.searchParams.get('code');
    
    if (!code) {
      return NextResponse.redirect(`${baseUrl}?error=no_code`);
    }

    try {
      const tokenResponse = await fetch(`https://${auth0Domain}/oauth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          grant_type: 'authorization_code',
          client_id: auth0ClientId,
          client_secret: auth0ClientSecret,
          code,
          redirect_uri: `${baseUrl}/api/auth/callback`,
          audience: auth0Audience,
        }),
      });

      const tokens = await tokenResponse.json();

      if (!tokenResponse.ok) {
        throw new Error(tokens.error_description || 'Token exchange failed');
      }

      const response = NextResponse.redirect(baseUrl);
      response.cookies.set('auth0_session', JSON.stringify(tokens), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 24 * 7,
        path: '/',
      });

      return response;
    } catch (error) {
      console.error('Auth error:', error);
      return NextResponse.redirect(`${baseUrl}?error=auth_failed`);
    }
  }

  if (auth0 === 'me') {
    const session = request.cookies.get('auth0_session');
    
    if (!session) {
      return NextResponse.json({ error: 'Not authenticated' }, { status: 401 });
    }

    try {
      const tokens = JSON.parse(session.value);
      
      const userResponse = await fetch(`https://${auth0Domain}/userinfo`, {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
        },
      });

      if (!userResponse.ok) {
        throw new Error('Failed to fetch user info');
      }

      const user = await userResponse.json();
      
      return NextResponse.json({ user, tokens });
    } catch (error) {
      console.error('User info error:', error);
      return NextResponse.json({ error: 'Failed to get user info' }, { status: 500 });
    }
  }

  return NextResponse.json({ error: 'Invalid auth route' }, { status: 404 });
}
```

#### 3.5 外部画像設定
`next.config.ts`:
```typescript
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**.googleusercontent.com',
      },
      {
        protocol: 'https',
        hostname: '**.auth0.com',
      },
      {
        protocol: 'https',
        hostname: 's.gravatar.com',
      },
    ],
  },
};

export default nextConfig;
```

#### 3.6 ホームページを作成
`src/app/page.tsx`:
```typescript
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';

interface User {
  name?: string;
  email?: string;
  picture?: string;
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    fetch('/api/auth/me')
      .then(res => {
        if (res.ok) return res.json();
        throw new Error('Not authenticated');
      })
      .then(data => setUser(data.user))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-black">
        <p className="text-zinc-600 dark:text-zinc-400">Loading...</p>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-black">
      <main className="flex min-h-screen w-full max-w-3xl flex-col items-center justify-center gap-8 px-6">
        <div className="text-center">
          <h1 className="text-4xl font-bold tracking-tight text-black dark:text-white mb-4">
            Auth0 + Rails + Next.js
          </h1>
          <p className="text-lg text-zinc-600 dark:text-zinc-400">
            Simple authentication demo
          </p>
        </div>

        {user ? (
          <div className="flex flex-col items-center gap-6 bg-white dark:bg-zinc-900 p-8 rounded-lg shadow-lg">
            {user.picture && (
              <Image
                src={user.picture}
                alt={user.name || 'User'}
                width={80}
                height={80}
                className="rounded-full"
              />
            )}
            <div className="text-center">
              <h2 className="text-2xl font-semibold text-black dark:text-white mb-2">
                Welcome, {user.name || user.email}!
              </h2>
              {user.email && (
                <p className="text-zinc-600 dark:text-zinc-400">{user.email}</p>
              )}
            </div>
            <div className="flex flex-col sm:flex-row gap-4">
              <button
                onClick={() => router.push('/dashboard')}
                className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-medium"
              >
                Go to Dashboard
              </button>
              <a
                href="/api/auth/logout"
                className="px-6 py-3 bg-zinc-800 text-white rounded-lg hover:bg-zinc-700 transition-colors font-medium text-center"
              >
                Logout
              </a>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-6">
            <p className="text-zinc-600 dark:text-zinc-400">
              You are not logged in
            </p>
            <a
              href="/api/auth/login"
              className="px-8 py-4 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors font-semibold text-lg"
            >
              Login with Auth0
            </a>
          </div>
        )}
      </main>
    </div>
  );
}
```

#### 3.7 ダッシュボードページを作成
`src/app/dashboard/page.tsx`:
```typescript
'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';

interface User {
  name?: string;
  email?: string;
  picture?: string;
}

interface ApiResponse {
  message?: string;
  error?: string;
}

export default function Dashboard() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [publicData, setPublicData] = useState<ApiResponse | null>(null);
  const [privateData, setPrivateData] = useState<ApiResponse | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const router = useRouter();

  useEffect(() => {
    fetch('/api/auth/me')
      .then(res => {
        if (!res.ok) throw new Error('Not authenticated');
        return res.json();
      })
      .then(data => {
        setUser(data.user);
        setAccessToken(data.tokens?.access_token);
      })
      .catch(() => {
        router.push('/');
      })
      .finally(() => setLoading(false));
  }, [router]);

  const testPublicApi = async () => {
    try {
      const res = await fetch('http://localhost:3001/api/v1/public');
      const data = await res.json();
      setPublicData(data);
    } catch {
      setPublicData({ error: 'Failed to fetch public API' });
    }
  };

  const testPrivateApi = async () => {
    if (!accessToken) {
      setPrivateData({ error: 'No access token available' });
      return;
    }

    try {
      const res = await fetch('http://localhost:3001/api/v1/private', {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      const data = await res.json();
      setPrivateData(data);
    } catch {
      setPrivateData({ error: 'Failed to fetch private API' });
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-50 dark:bg-black">
        <p className="text-zinc-600 dark:text-zinc-400">Loading...</p>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black py-12 px-4">
      <div className="max-w-4xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <h1 className="text-3xl font-bold text-black dark:text-white">
            Dashboard
          </h1>
          <div className="flex gap-4">
            <button
              onClick={() => router.push('/')}
              className="px-4 py-2 text-zinc-600 dark:text-zinc-400 hover:text-black dark:hover:text-white"
            >
              Home
            </button>
            <a
              href="/api/auth/logout"
              className="px-4 py-2 bg-zinc-800 text-white rounded hover:bg-zinc-700"
            >
              Logout
            </a>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4 text-black dark:text-white">
              User Information
            </h2>
            <div className="space-y-2 text-zinc-700 dark:text-zinc-300">
              <p><strong>Name:</strong> {user.name}</p>
              <p><strong>Email:</strong> {user.email}</p>
            </div>
          </div>

          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4 text-black dark:text-white">
              Rails API Testing
            </h2>
            
            <div className="space-y-4">
              <div>
                <button
                  onClick={testPublicApi}
                  className="px-6 py-2 bg-green-600 text-white rounded hover:bg-green-700 mb-2"
                >
                  Test Public API
                </button>
                {publicData && (
                  <div className="bg-zinc-100 dark:bg-zinc-800 p-4 rounded">
                    <pre className="text-sm text-zinc-800 dark:text-zinc-200">
                      {JSON.stringify(publicData, null, 2)}
                    </pre>
                  </div>
                )}
              </div>

              <div>
                <button
                  onClick={testPrivateApi}
                  className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 mb-2"
                >
                  Test Private API (Authenticated)
                </button>
                {privateData && (
                  <div className="bg-zinc-100 dark:bg-zinc-800 p-4 rounded">
                    <pre className="text-sm text-zinc-800 dark:text-zinc-200">
                      {JSON.stringify(privateData, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>

          {accessToken && (
            <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
              <h2 className="text-xl font-semibold mb-4 text-black dark:text-white">
                Access Token
              </h2>
              <div className="bg-zinc-100 dark:bg-zinc-800 p-4 rounded break-all text-sm text-zinc-800 dark:text-zinc-200">
                {accessToken}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
```

#### 3.8 Next.jsサーバー起動
```bash
npm run dev
```

### Phase 4: 動作確認

1. **ブラウザでアクセス**: http://localhost:3000
2. **「Login with Auth0」をクリック**
3. **Auth0のログイン画面で認証**
4. **ホームページにリダイレクト**されてユーザー情報が表示される
5. **「Go to Dashboard」をクリック**
6. **「Test Public API」をクリック** → 成功メッセージが表示される
7. **「Test Private API」をクリック** → JWT認証後に成功メッセージが表示される

## 🔐 How It Works

### Authentication Flow

```
1. ユーザーがホームページにアクセス
   ↓
2. 「Login with Auth0」ボタンをクリック
   ↓
3. /api/auth/login にリダイレクト
   ↓
4. Auth0の認証ページへ (audience付き)
   ↓
5. 認証成功
   ↓
6. /api/auth/callback へ戻る
   ↓
7. 認可コードをトークンに交換
   ↓
8. access_tokenとid_tokenを取得
   ↓
9. HTTP-only cookieに保存
   ↓
10. ホームページへリダイレクト
```

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
- Auth0の公開鍵（JWKS）を使用してトークンの署名を検証
- issuer (iss) と audience (aud) を検証
- トークンの有効期限を確認

## 🛠️ Technologies

| Layer | Technology | Version |
|-------|-----------|---------|
| **Frontend** | Next.js | 16.0.0 |
| | React | 19.2.0 |
| | TypeScript | ^5 |
| | Tailwind CSS | ^4 |
| **Backend** | Rails | 8.1.0 |
| | Ruby | 3.3.9+ |
| | SQLite | 3 |
| **Auth** | Auth0 | - |
| | JWT | 3.1.2 |
| **Dev Tools** | dotenv-rails | 3.1.8 |
| | rack-cors | 3.0.0 |

## 📝 API Endpoints

### Frontend (Next.js)
| Endpoint | Description |
|----------|-------------|
| `GET /api/auth/login` | Auth0ログインを開始 |
| `GET /api/auth/callback` | Auth0認証コールバック |
| `GET /api/auth/logout` | ログアウト処理 |
| `GET /api/auth/me` | 現在のユーザー情報を取得 |

### Backend (Rails)
| Endpoint | Auth Required | Description |
|----------|--------------|-------------|
| `GET /api/v1/public` | ❌ | 公開エンドポイント |
| `GET /api/v1/private` | ✅ | 保護されたエンドポイント（JWT必須） |

## 🐛 Troubleshooting

### よくある問題と解決方法

#### 1. CORS エラー
**症状**: ブラウザコンソールに `CORS policy` エラー

**解決**:
- Railsの `.env` で `FRONTEND_URL=http://localhost:3000` を確認
- `config/initializers/cors.rb` の設定を確認
- Railsサーバーを再起動

#### 2. JWT検証エラー: Invalid issuer
**症状**: `Expected ["https://..."], received https://.../`

**解決**: `json_web_token.rb` で issuer に配列を使用:
```ruby
iss: [auth0_issuer, "#{auth0_issuer}/"],
```

#### 3. SSL証明書エラー
**症状**: `SSL_connect returned=1 errno=0`

**解決**: `json_web_token.rb` で開発環境ではSSL検証をスキップ:
```ruby
http.verify_mode = Rails.env.production? ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
```

#### 4. 環境変数が読み込まれない
**症状**: `AUTH0_DOMAIN` が `nil`

**解決**:
```bash
# Gemfileに追加
gem "dotenv-rails", groups: [:development, :test]

# インストール
bundle install

# サーバー再起動
```

#### 5. Auth0 callback URLエラー
**症状**: Auth0から `Callback URL mismatch`

**解決**: Auth0ダッシュボードで以下を確認:
- Allowed Callback URLs: `http://localhost:3000/api/auth/callback`
- 正確に一致しているか確認（末尾スラッシュなし）

## 📄 環境変数一覧

### Backend (.env)
```bash
# Auth0 settings (domain without https://)
AUTH0_DOMAIN=dev-xxx.auth0.com
AUTH0_API_IDENTIFIER=https://my-rails-api

# Frontend URL for CORS
FRONTEND_URL=http://localhost:3000
```

### Frontend (.env.local)
```bash
# Auth0 Configuration
AUTH0_DOMAIN=dev-xxx.auth0.com
AUTH0_CLIENT_ID=abc123...
AUTH0_CLIENT_SECRET=xyz789...
AUTH0_BASE_URL=http://localhost:3000
AUTH0_AUDIENCE=https://my-rails-api

# Backend API URL
NEXT_PUBLIC_API_URL=http://localhost:3001
```

## 🚀 本番環境へのデプロイ

### 1. 新しいAuth0テナントを作成（推奨）
```
Production Tenant: prod-myapp.auth0.com
```

### 2. 環境変数を本番用に更新
```bash
# Backend
AUTH0_DOMAIN=prod-myapp.auth0.com
FRONTEND_URL=https://yourdomain.com

# Frontend  
AUTH0_BASE_URL=https://yourdomain.com
AUTH0_AUDIENCE=https://api.yourdomain.com
```

### 3. Auth0 Application設定を更新
```
Allowed Callback URLs:
https://yourdomain.com/api/auth/callback

Allowed Logout URLs:
https://yourdomain.com

Allowed Web Origins:
https://yourdomain.com
```

## 📚 参考リンク

- [Auth0 Documentation](https://auth0.com/docs)
- [Next.js Documentation](https://nextjs.org/docs)
- [Rails Guides](https://guides.rubyonrails.org/)
- [JWT.io](https://jwt.io/)

## 📄 License

MIT

---

**作成日**: 2025年10月24日  
**Auth0 + Rails + Next.js による簡単な認証システムの実装例**

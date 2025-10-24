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
        maxAge: 60 * 60 * 24 * 7, // 1 week
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

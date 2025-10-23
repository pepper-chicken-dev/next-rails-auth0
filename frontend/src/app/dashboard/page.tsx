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
    // Check authentication
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
    return null; // Will redirect
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
          {/* User Info */}
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4 text-black dark:text-white">
              User Information
            </h2>
            <div className="space-y-2 text-zinc-700 dark:text-zinc-300">
              <p><strong>Name:</strong> {user.name}</p>
              <p><strong>Email:</strong> {user.email}</p>
            </div>
          </div>

          {/* API Testing */}
          <div className="bg-white dark:bg-zinc-900 p-6 rounded-lg shadow">
            <h2 className="text-xl font-semibold mb-4 text-black dark:text-white">
              Rails API Testing
            </h2>
            
            <div className="space-y-4">
              {/* Public API */}
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

              {/* Private API */}
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

          {/* Access Token Info */}
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

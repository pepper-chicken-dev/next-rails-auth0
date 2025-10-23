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

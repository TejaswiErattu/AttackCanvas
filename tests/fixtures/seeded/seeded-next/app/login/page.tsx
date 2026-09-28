"use client";

import { useState } from "react";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(event: { preventDefault(): void }) {
    event.preventDefault();
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!response.ok) return setError("Sign-in failed");
    const { token } = await response.json();
    // SEEDED:n-token-storage
    localStorage.setItem("accessToken", token);
    window.location.assign("/");
  }

  return (
    <form onSubmit={submit}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" />
      <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" />
      {error && <p role="alert">{error}</p>}
      <button type="submit">Sign in</button>
    </form>
  );
}

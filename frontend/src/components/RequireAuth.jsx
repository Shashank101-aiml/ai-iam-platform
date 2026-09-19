import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

const TOKEN_KEY = 'aiiam_operator_token';

/**
 * Gates the dashboard behind a logged-in session. Presence-only check
 * — it looks for the token services/api.js already reads/writes under
 * TOKEN_KEY, it does not decode or validate the JWT client-side. If a
 * token is missing, redirect to /login; if a dashboard API call later
 * gets a real 401 (token expired/revoked), that surfaces through the
 * existing "Backend unreachable" error panel rather than a silent
 * redirect — this component only handles the "never logged in at all"
 * case, which is the one thing that didn't exist before this overhaul.
 */
export default function RequireAuth({ children }) {
  const location = useLocation();
  const token = localStorage.getItem(TOKEN_KEY);

  if (!token) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  return children;
}

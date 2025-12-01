/**
 * Generates and manages unique session IDs for each browser tab/window
 * This allows the same user to have multiple cursors (one per tab)
 */

const SESSION_ID_KEY = 'grafana.exploreMap.sessionId';

/**
 * Generates a unique session ID for this browser tab/window
 * Uses sessionStorage so each tab gets its own ID
 * @returns A unique session ID string
 */
export function getOrCreateSessionId(): string {
  // Use sessionStorage (not localStorage) so each tab gets a unique ID
  let sessionId = sessionStorage.getItem(SESSION_ID_KEY);

  if (!sessionId) {
    // Generate a new session ID: timestamp + random string
    sessionId = `session-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
    sessionStorage.setItem(SESSION_ID_KEY, sessionId);
  }

  return sessionId;
}

/**
 * Clears the session ID (useful for testing or cleanup)
 */
export function clearSessionId(): void {
  sessionStorage.removeItem(SESSION_ID_KEY);
}

/**
 * Generates a consistent color for a user based on their userId
 * Uses a predefined palette of visually distinct colors
 */

const USER_COLORS = [
  '#FF6B6B', // Red
  '#4ECDC4', // Teal
  '#45B7D1', // Blue
  '#FFA07A', // Light Salmon
  '#98D8C8', // Mint
  '#F7DC6F', // Yellow
  '#BB8FCE', // Purple
  '#85C1E2', // Sky Blue
  '#F8B88B', // Peach
  '#52BE80', // Green
  '#FF85A1', // Pink
  '#5DADE2', // Light Blue
  '#F39C12', // Orange
  '#AF7AC5', // Lavender
  '#48C9B0', // Turquoise
];

/**
 * Simple string hash function for consistent color assignment
 */
function hashString(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash);
}

/**
 * Generates a consistent color for a user
 * @param userId - The user's unique identifier
 * @returns A hex color string
 */
export function getUserColor(userId: string): string {
  const hash = hashString(userId);
  const index = hash % USER_COLORS.length;
  return USER_COLORS[index];
}

/**
 * Gets or generates a random color and stores it in localStorage
 * This ensures the user gets the same color across sessions
 * @returns A hex color string
 */
export function getOrGenerateUserColor(): string {
  const storageKey = 'grafana.exploreMap.userColor';

  // Try to get existing color from localStorage
  const storedColor = localStorage.getItem(storageKey);
  if (storedColor) {
    return storedColor;
  }

  // Generate a new random color
  const randomIndex = Math.floor(Math.random() * USER_COLORS.length);
  const color = USER_COLORS[randomIndex];

  // Store for future use
  localStorage.setItem(storageKey, color);

  return color;
}

/**
 * Format bytes to human-readable string
 */
export function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined || bytes === null) return '-';
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

/**
 * Format Unix timestamp to expiration string
 */
export function formatExpire(timestamp: number | undefined): string {
  if (timestamp === undefined || timestamp === null) return '-';
  if (timestamp === 0) return '永不过期';
  const now = Date.now() / 1000;
  if (timestamp < now) return '已过期';
  const days = Math.floor((timestamp - now) / 86400);
  return `${days} 天`;
}

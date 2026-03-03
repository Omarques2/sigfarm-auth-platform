export function shouldShowPasswordMismatch(primaryPassword: string, confirmationPassword: string): boolean {
  if (primaryPassword.length === 0 || confirmationPassword.length === 0) return false;
  return primaryPassword !== confirmationPassword;
}

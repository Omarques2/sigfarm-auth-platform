type PasswordChecklistVisibilityInput = {
  primaryPassword: string;
  confirmationPassword?: string;
  isStrongPassword: boolean;
};

export function shouldShowPasswordChecklist(input: PasswordChecklistVisibilityInput): boolean {
  const hasAnyPasswordInput =
    input.primaryPassword.length > 0 || (input.confirmationPassword?.length ?? 0) > 0;

  return hasAnyPasswordInput && !input.isStrongPassword;
}

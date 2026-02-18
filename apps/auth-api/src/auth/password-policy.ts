export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

export const PASSWORD_POLICY_MESSAGE =
  "A senha deve ter no minimo 12 caracteres, com letra minuscula, maiuscula, numero e caractere especial.";

type Rule = {
  test: (password: string) => boolean;
};

const RULES: Rule[] = [
  { test: (password) => password.length >= PASSWORD_MIN_LENGTH },
  { test: (password) => password.length <= PASSWORD_MAX_LENGTH },
  { test: (password) => /[a-z]/.test(password) },
  { test: (password) => /[A-Z]/.test(password) },
  { test: (password) => /\d/.test(password) },
  { test: (password) => /[^A-Za-z\d]/.test(password) },
];

export function isPasswordPolicyCompliant(password: string): boolean {
  return RULES.every((rule) => rule.test(password));
}

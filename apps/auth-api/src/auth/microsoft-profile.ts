type MicrosoftProfileLike = {
  email?: unknown;
};

type MicrosoftProfileUserMap = {
  emailVerified?: boolean;
};

export function mapMicrosoftProfileToUser(profile: MicrosoftProfileLike): MicrosoftProfileUserMap {
  const email = typeof profile.email === "string" ? profile.email.trim() : "";
  if (email.length === 0) {
    return {};
  }

  // Microsoft sign-in should not block on app-level email verification.
  return { emailVerified: true };
}

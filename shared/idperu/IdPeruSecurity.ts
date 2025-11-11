/**
 * Security utilities for IDPerú authentication flow
 */

/**
 * Validates that an authorization code is not empty and has a valid format
 * @param code The authorization code to validate
 * @returns true if valid, false otherwise
 */
export function validateAuthCode(code: string): boolean {
  if (!code || typeof code !== 'string') {
    return false;
  }

  // Authorization codes are typically alphanumeric strings
  // Minimum length check (OAuth2 spec doesn't specify max, but typically 20-200 chars)
  if (code.length < 10 || code.length > 500) {
    return false;
  }

  // Basic format validation: should not contain spaces or control characters
  if (/[\s\r\n\t]/.test(code)) {
    return false;
  }

  return true;
}

/**
 * Validates state parameter if used (for CSRF protection)
 * @param receivedState The state received from the callback
 * @param expectedState The state that was originally sent
 * @returns true if states match, false otherwise
 */
export function validateState(
  receivedState: string | null | undefined,
  expectedState: string | null | undefined,
): boolean {
  // If state is not used, both should be null/undefined
  if (!receivedState && !expectedState) {
    return true;
  }

  // If one is provided, both must be provided and match
  if (!receivedState || !expectedState) {
    return false;
  }

  return receivedState === expectedState;
}

/**
 * Cleans up sensitive data from memory
 * This is a helper function to ensure sensitive strings are overwritten
 * Note: In JavaScript, strings are immutable, so this is mainly for code clarity
 * @param data Sensitive data to "clean" (for documentation/logging purposes)
 */
export function cleanupSensitiveData(data: string): void {
  // In JavaScript, strings are immutable, so we can't truly overwrite them
  // This function serves as documentation that cleanup should happen
  // The actual cleanup happens when variables go out of scope and are garbage collected
  // For critical data, consider using typed arrays that can be zeroed
  if (data) {
    // Mark for garbage collection by removing reference
    // In practice, just ensure the variable is set to null after use
  }
}

/**
 * Validates that required PKCE parameters are present
 * @param codeVerifier The code_verifier
 * @param codeChallenge The code_challenge
 * @returns true if both are valid, false otherwise
 */
export function validatePKCEParams(
  codeVerifier: string | null | undefined,
  codeChallenge: string | null | undefined,
): boolean {
  if (!codeVerifier || !codeChallenge) {
    return false;
  }

  // Validate code_verifier length (RFC 7636: 43-128 characters)
  if (codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false;
  }

  // Validate code_challenge format (base64url, typically 43 characters)
  if (codeChallenge.length < 43 || codeChallenge.length > 128) {
    return false;
  }

  return true;
}

/**
 * Sanitizes error messages to avoid leaking sensitive information
 * @param error The error object or message
 * @returns Sanitized error message safe for logging
 */
export function sanitizeErrorMessage(error: any): string {
  if (!error) {
    return 'Unknown error';
  }

  const message =
    typeof error === 'string' ? error : error.message || 'Unknown error';

  // Remove potential sensitive data patterns
  let sanitized = message
    .replace(/code_verifier[=:]\s*[^\s,}]+/gi, 'code_verifier=***')
    .replace(/code[=:]\s*[^\s,}]+/gi, 'code=***')
    .replace(/token[=:]\s*[^\s,}]+/gi, 'token=***')
    .replace(/password[=:]\s*[^\s,}]+/gi, 'password=***')
    .replace(/secret[=:]\s*[^\s,}]+/gi, 'secret=***');

  return sanitized;
}

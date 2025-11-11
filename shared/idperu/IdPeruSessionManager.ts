import {generatePKCEPair} from './pkceUtils';

/**
 * Session manager for IDPerú PKCE flow
 * Stores code_verifier securely in memory during the authentication session
 */
class IdPeruSessionManager {
  private codeVerifier: string | null = null;
  private codeChallenge: string | null = null;
  private sessionStartTime: number | null = null;
  private readonly SESSION_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes

  /**
   * Generates and stores PKCE code_verifier and code_challenge
   * @param verifierLength Optional length for code_verifier (default: 64)
   * @returns Object with codeVerifier and codeChallenge
   */
  async generatePKCE(verifierLength: number = 64): Promise<{
    codeVerifier: string;
    codeChallenge: string;
  }> {
    // Clear any existing session
    this.clearSession();

    const {codeVerifier, codeChallenge} = await generatePKCEPair(
      verifierLength,
    );

    this.codeVerifier = codeVerifier;
    this.codeChallenge = codeChallenge;
    this.sessionStartTime = Date.now();

    return {codeVerifier, codeChallenge};
  }

  /**
   * Gets the current code_verifier if session is valid
   * @returns code_verifier or null if session expired/cleared
   */
  getCodeVerifier(): string | null {
    if (!this.codeVerifier || !this.sessionStartTime) {
      return null;
    }

    // Check if session has expired
    const elapsed = Date.now() - this.sessionStartTime;
    if (elapsed > this.SESSION_TIMEOUT_MS) {
      this.clearSession();
      return null;
    }

    return this.codeVerifier;
  }

  /**
   * Gets the current code_challenge if session is valid
   * @returns code_challenge or null if session expired/cleared
   */
  getCodeChallenge(): string | null {
    if (!this.codeChallenge || !this.sessionStartTime) {
      return null;
    }

    // Check if session has expired
    const elapsed = Date.now() - this.sessionStartTime;
    if (elapsed > this.SESSION_TIMEOUT_MS) {
      this.clearSession();
      return null;
    }

    return this.codeChallenge;
  }

  /**
   * Clears the current session and all stored PKCE data
   * Should be called after successful token exchange or on error
   */
  clearSession(): void {
    // Overwrite with null to help garbage collection
    this.codeVerifier = null;
    this.codeChallenge = null;
    this.sessionStartTime = null;
  }

  /**
   * Checks if there is an active session
   * @returns true if session exists and is valid, false otherwise
   */
  hasActiveSession(): boolean {
    return this.getCodeVerifier() !== null;
  }
}

// Export singleton instance
export const idPeruSessionManager = new IdPeruSessionManager();

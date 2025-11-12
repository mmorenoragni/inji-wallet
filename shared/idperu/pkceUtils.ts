import {sha256} from '@noble/hashes/sha256';
import {generateSecureRandom} from 'react-native-securerandom';
import base64url from 'base64url-universal';

/**
 * Generates a random base64url-encoded string for PKCE code_verifier
 * @param length Length of the random string (default: 64, recommended: 43-128)
 * @returns Base64url-encoded random string
 */
export async function randomBase64Url(length: number = 64): Promise<string> {
  if (length < 43 || length > 128) {
    throw new Error(
      'PKCE code_verifier length must be between 43 and 128 characters',
    );
  }

  // Generate secure random bytes
  // We need length * 3/4 bytes to get approximately 'length' base64url characters
  const byteLength = Math.ceil((length * 3) / 4);
  const randomBytes = await generateSecureRandom(byteLength);

  // Convert to base64url
  const base64urlString = base64url.encode(randomBytes);

  // Trim to desired length (base64url encoding may produce slightly more characters)
  return base64urlString.substring(0, length);
}

/**
 * Generates PKCE code_challenge from code_verifier using SHA256
 * @param codeVerifier The code_verifier string
 * @returns Base64url-encoded SHA256 hash of the code_verifier
 */
export async function sha256Base64Url(codeVerifier: string): Promise<string> {
  if (!codeVerifier || codeVerifier.length < 43 || codeVerifier.length > 128) {
    throw new Error(
      'Invalid code_verifier: must be between 43 and 128 characters',
    );
  }

  // Convert string to Uint8Array
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);

  // Compute SHA256 hash
  const hash = sha256(data);

  // Encode to base64url (without padding)
  return base64url.encode(hash);
}

/**
 * Generates both code_verifier and code_challenge for PKCE
 * @param verifierLength Optional length for code_verifier (default: 64)
 * @returns Object with codeVerifier and codeChallenge
 */
export async function generatePKCEPair(
  verifierLength: number = 64,
): Promise<{codeVerifier: string; codeChallenge: string}> {
  const codeVerifier = await randomBase64Url(verifierLength);
  const codeChallenge = await sha256Base64Url(codeVerifier);

  return {
    codeVerifier,
    codeChallenge,
  };
}

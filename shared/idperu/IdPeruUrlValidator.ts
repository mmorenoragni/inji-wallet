/**
 * URL validation and verification utilities for IDPerú authorization URLs
 */

export interface UrlValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  url: string;
  parameters: Record<string, string>;
}

/**
 * Validates that an IDPerú authorization URL is correctly constructed
 * @param url The authorization URL to validate
 * @returns Validation result with details
 */
export function validateIdPeruUrl(url: string): UrlValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const parameters: Record<string, string> = {};

  try {
    const urlObj = new URL(url);

    // Extract all parameters
    urlObj.searchParams.forEach((value, key) => {
      parameters[key] = value;
    });

    // Required parameters validation
    const requiredParams = [
      'client_id',
      'redirect_uri',
      'scope',
      'response_type',
      'code_challenge',
      'code_challenge_method',
    ];

    for (const param of requiredParams) {
      if (!parameters[param]) {
        errors.push(`Missing required parameter: ${param}`);
      }
    }

    // Validate response_type
    if (parameters.response_type && parameters.response_type !== 'code') {
      errors.push(
        `Invalid response_type: expected 'code', got '${parameters.response_type}'`,
      );
    }

    // Validate code_challenge_method
    if (
      parameters.code_challenge_method &&
      parameters.code_challenge_method !== 'S256'
    ) {
      errors.push(
        `Invalid code_challenge_method: expected 'S256', got '${parameters.code_challenge_method}'`,
      );
    }

    // Validate scope
    if (parameters.scope && !parameters.scope.includes('openid')) {
      warnings.push("Scope should include 'openid'");
    }

    // Validate code_challenge format (base64url, typically 43 chars)
    if (parameters.code_challenge) {
      const challengeLength = parameters.code_challenge.length;
      if (challengeLength < 43 || challengeLength > 128) {
        warnings.push(
          `code_challenge length (${challengeLength}) is unusual. Expected 43-128 characters.`,
        );
      }

      // Check for invalid base64url characters
      if (!/^[A-Za-z0-9_-]+$/.test(parameters.code_challenge)) {
        errors.push(
          'code_challenge contains invalid characters (must be base64url)',
        );
      }
    }

    // Validate redirect_uri format
    if (parameters.redirect_uri) {
      if (
        !parameters.redirect_uri.startsWith('http://') &&
        !parameters.redirect_uri.startsWith('https://') &&
        !parameters.redirect_uri.includes('://')
      ) {
        // Custom scheme (e.g., io.mosip.residentapp.inji://oauthredirect)
        if (!parameters.redirect_uri.includes('://')) {
          warnings.push(
            'redirect_uri appears to be a custom scheme. Ensure it matches the app configuration.',
          );
        }
      }
    }

    // Check for acr_values (optional but recommended for RENIEC)
    if (!parameters.acr_values) {
      warnings.push(
        'acr_values parameter is missing. This may be required for RENIEC authentication.',
      );
    } else if (parameters.acr_values === 'pki_dnie') {
      // This is correct for RENIEC
    }

    // Validate URL scheme
    if (urlObj.protocol !== 'https:') {
      warnings.push(
        `URL uses ${urlObj.protocol} instead of https. This may be insecure.`,
      );
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      url,
      parameters,
    };
  } catch (e: any) {
    return {
      isValid: false,
      errors: [`Invalid URL format: ${e.message}`],
      warnings: [],
      url,
      parameters: {},
    };
  }
}

/**
 * Formats URL for display/debugging (masks sensitive data)
 * @param url The URL to format
 * @returns Formatted URL string with masked sensitive parts
 */
export function formatUrlForDisplay(url: string): string {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);

    // Mask code_challenge (show first 10 chars)
    if (params.has('code_challenge')) {
      const challenge = params.get('code_challenge') || '';
      params.set('code_challenge', challenge.substring(0, 10) + '...');
    }

    urlObj.search = params.toString();
    return urlObj.toString();
  } catch {
    return url;
  }
}

/**
 * Compares expected URL parameters with actual URL
 * @param url The URL to check
 * @param expectedParams Expected parameters and values
 * @returns Object with comparison results
 */
export function compareUrlParams(
  url: string,
  expectedParams: Record<string, string | null>,
): {
  matches: boolean;
  missing: string[];
  incorrect: Array<{param: string; expected: string; actual: string}>;
  extra: string[];
} {
  try {
    const urlObj = new URL(url);
    const actualParams: Record<string, string> = {};
    urlObj.searchParams.forEach((value, key) => {
      actualParams[key] = value;
    });

    const missing: string[] = [];
    const incorrect: Array<{param: string; expected: string; actual: string}> =
      [];
    const extra: string[] = [];

    // Check expected parameters
    for (const [key, expectedValue] of Object.entries(expectedParams)) {
      if (!(key in actualParams)) {
        if (expectedValue !== null) {
          // null means parameter is optional
          missing.push(key);
        }
      } else if (expectedValue !== null && actualParams[key] !== expectedValue) {
        incorrect.push({
          param: key,
          expected: expectedValue,
          actual: actualParams[key],
        });
      }
    }

    // Check for extra parameters
    for (const key of Object.keys(actualParams)) {
      if (!(key in expectedParams)) {
        extra.push(key);
      }
    }

    return {
      matches: missing.length === 0 && incorrect.length === 0,
      missing,
      incorrect,
      extra,
    };
  } catch (e: any) {
    return {
      matches: false,
      missing: [],
      incorrect: [],
      extra: [],
    };
  }
}


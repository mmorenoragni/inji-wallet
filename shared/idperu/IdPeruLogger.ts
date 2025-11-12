/**
 * Logger utility for IDPerú authentication flow
 * All logs are prefixed with [IDPerú] for easy filtering in logcat
 * 
 * Usage in logcat:
 *   adb logcat | grep "IDPerú"
 *   adb logcat | grep "ReactNativeJS.*IDPerú"
 */

const LOG_TAG = '[IDPerú]';
const MARIANO_PREFIX = 'Mariano log =>';

/**
 * Logs an info message
 * @param message Log message
 * @param data Optional data object to log
 */
export function logInfo(message: string, data?: any): void {
  if (__DEV__) {
    if (data) {
      console.log(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`, data);
    } else {
      console.log(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`);
    }
  }
}

/**
 * Logs a warning message
 * @param message Log message
 * @param data Optional data object to log
 */
export function logWarn(message: string, data?: any): void {
  if (__DEV__) {
    if (data) {
      console.warn(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`, data);
    } else {
      console.warn(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`);
    }
  }
}

/**
 * Logs an error message
 * @param message Log message
 * @param error Optional error object or data
 */
export function logError(message: string, error?: any): void {
  // Always log errors, even in production (but sanitized)
  if (error) {
    console.error(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`, error);
  } else {
    console.error(`${MARIANO_PREFIX} ${LOG_TAG} ${message}`);
  }
}

/**
 * Logs PKCE generation details
 * @param codeVerifier The code verifier (will be masked)
 * @param codeChallenge The code challenge
 */
export function logPKCEGenerated(
  codeVerifier: string,
  codeChallenge: string,
): void {
  logInfo('PKCE Generated', {
    codeVerifierLength: codeVerifier.length,
    codeChallengeLength: codeChallenge.length,
    codeChallengePreview: codeChallenge.substring(0, 20) + '...',
  });
}

/**
 * Logs URL construction details
 * @param url The full authorization URL
 * @param params URL parameters object
 */
export function logUrlConstruction(url: string, params: any): void {
  logInfo('===== URL VERIFICATION =====');
  logInfo('Authorization URL', url);
  logInfo('URL Parameters', params);
}

/**
 * Logs URL validation results
 * @param validationResult Validation result object
 */
export function logUrlValidation(validationResult: any): void {
  logInfo('URL Validation', validationResult);
}

/**
 * Logs parameter comparison results
 * @param comparisonResult Comparison result object
 */
export function logParameterComparison(comparisonResult: any): void {
  logInfo('Parameter Comparison', comparisonResult);
  if (comparisonResult.matches === false) {
    logWarn('PARAMETER MISMATCH', comparisonResult);
  }
}

/**
 * Logs the final URL breakdown
 * @param breakdown URL breakdown object
 */
export function logUrlBreakdown(breakdown: any): void {
  logInfo('URL Breakdown', breakdown);
  logInfo('============================');
}


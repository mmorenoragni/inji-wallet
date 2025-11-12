/**
 * ID Peru URL Validator
 * Provides utilities for validating and processing ID Peru URLs
 */

/**
 * Validates if a URL is a valid ID Peru authentication URL
 * @param url - The URL to validate
 * @returns true if the URL is valid, false otherwise
 */
export const validateIdPeruUrl = (url: string): boolean => {
  if (!url || typeof url !== 'string') {
    return false;
  }

  try {
    const urlObj = new URL(url);

    // Check if the URL has required components
    if (!urlObj.protocol || !urlObj.hostname) {
      return false;
    }

    // Check for valid protocol (http or https)
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
};

/**
 * Formats a URL for display purposes (removes sensitive parameters)
 * @param url - The URL to format
 * @returns Formatted URL string safe for display
 */
export const formatUrlForDisplay = (url: string): string => {
  if (!url || typeof url !== 'string') {
    return '';
  }

  try {
    const urlObj = new URL(url);

    // Remove sensitive query parameters
    const sensitiveParams = ['code', 'token'];
    sensitiveParams.forEach(param => {
      urlObj.searchParams.delete(param);
    });

    // Return formatted URL
    return `${urlObj.origin}${urlObj.pathname}${
      urlObj.searchParams.toString() ? '?' + urlObj.searchParams.toString() : ''
    }`;
  } catch (error) {
    return url;
  }
};

/**
 * Compares URL parameters between two URLs
 * @param url1 - First URL to compare
 * @param url2 - Second URL to compare
 * @returns Object containing comparison results
 */
export const compareUrlParams = (
  url1: string,
  url2: string,
): {
  areSame: boolean;
  differences: string[];
  commonParams: string[];
} => {
  const result = {
    areSame: false,
    differences: [] as string[],
    commonParams: [] as string[],
  };

  try {
    const urlObj1 = new URL(url1);
    const urlObj2 = new URL(url2);

    // Get all parameter keys
    const params1 = Array.from(urlObj1.searchParams.keys());
    const params2 = Array.from(urlObj2.searchParams.keys());

    // Find common parameters
    result.commonParams = params1.filter(param => params2.includes(param));

    // Find differences
    const onlyInUrl1 = params1.filter(param => !params2.includes(param));
    const onlyInUrl2 = params2.filter(param => !params1.includes(param));

    result.differences = [
      ...onlyInUrl1.map(param => `${param} (only in URL 1)`),
      ...onlyInUrl2.map(param => `${param} (only in URL 2)`),
    ];

    // Check if URLs are the same (ignoring parameter order)
    result.areSame =
      urlObj1.origin === urlObj2.origin &&
      urlObj1.pathname === urlObj2.pathname &&
      params1.length === params2.length &&
      result.differences.length === 0;

    return result;
  } catch (error) {
    return result;
  }
};

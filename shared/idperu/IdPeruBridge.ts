import {NativeModules, Platform, NativeEventEmitter} from 'react-native';

const {IdPeruBridge} = NativeModules as {
  IdPeruBridge: {
    startAuth(
      qrData: string,
      packageName: string,
      activityName: string,
      inputKey: string,
    ): Promise<string>;
  };
};

export type IdPeruConfig = {
  // Android
  androidPackage?: string; // ej. "com.idperu.app"
  androidActivity?: string; // ej. "com.idperu.app.AuthActivity"
  androidInputKey?: string; // ej. "qr_data"
  // iOS
  iosScheme?: string; // ej. "idperu://auth"
  iosInputParam?: string; // ej. "qr_data"
};

/**
 * Starts IDPerú authentication flow with dynamic configuration
 * @param qrData QR data or authorization URL to pass to IDPerú
 * @param cfg Configuration object with platform-specific settings
 * @returns Promise that resolves with authorization code
 * @throws Error if configuration is invalid, IDPerú is not installed, or authentication fails
 */
export async function startIdPeruAuth(
  qrData: string,
  cfg: IdPeruConfig,
): Promise<string> {
  if (!IdPeruBridge) {
    throw new Error('IdPeruBridge native module is not available');
  }

  if (Platform.OS === 'android') {
    if (!cfg.androidPackage || !cfg.androidActivity || !cfg.androidInputKey) {
      throw new Error(
        'Missing Android config: androidPackage, androidActivity, and androidInputKey are required',
      );
    }

    try {
      // Android signature: (qrData, packageName, activityName, inputKey)
      console.log('[IDPerú] androidPackage:', cfg.androidPackage);
      console.log('[IDPerú] androidActivity:', cfg.androidActivity);
      console.log('[IDPerú] androidInputKey:', cfg.androidInputKey);
      const authCode = await IdPeruBridge.startAuth(
        qrData,
        cfg.androidPackage,
        cfg.androidActivity,
        cfg.androidInputKey,
      );
      return authCode;
    } catch (error: any) {
      // Handle specific error codes
      if (error.code === 'E_APP_NOT_INSTALLED') {
        console.log('[IDPerú] E_APP_NOT_INSTALLED', error);
        throw new Error(
          'IDPerú app is not installed. Please install IDPerú to continue.',
        );
      } else if (error.code === 'E_CANCELED') {
        throw new Error('Authentication was canceled by the user.');
      } else if (error.code === 'E_NO_ACTIVITY') {
        throw new Error('No activity available to start authentication.');
      } else if (error.code === 'E_INVALID_PARAMS') {
        throw new Error('Invalid parameters provided to IDPerú.');
      } else {
        throw new Error(
          error.message || 'Failed to start IDPerú authentication',
        );
      }
    }
  } else {
    // iOS implementation will be added in the future
    if (!cfg.iosScheme || !cfg.iosInputParam) {
      throw new Error(
        'Missing iOS config: iosScheme and iosInputParam are required',
      );
    }
    throw new Error('iOS support for IDPerú is not yet implemented');
  }
}

/**
 * Subscribes to IDPerú authentication result events (optional, for future iOS implementation)
 * @param handler Callback function that receives the authorization code
 * @returns Unsubscribe function
 */
export function subscribeAuthResult(
  handler: (code: string) => void,
): () => void {
  if (!IdPeruBridge) {
    throw new Error('IdPeruBridge native module is not available');
  }

  const emitter = new NativeEventEmitter(IdPeruBridge);
  const subscription = emitter.addListener('IdPeruAuthResult', payload => {
    if (payload?.code) {
      handler(payload.code);
    }
  });

  return () => subscription.remove();
}

export default {
  startIdPeruAuth,
  subscribeAuthResult,
};

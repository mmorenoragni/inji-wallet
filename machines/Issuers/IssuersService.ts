import NetInfo from '@react-native-community/netinfo';
import {NativeModules} from 'react-native';
import Cloud from '../../shared/CloudBackupAndRestoreUtils';
import getAllConfigurations, {CACHED_API} from '../../shared/api';
import {
  fetchKeyPair,
  generateKeyPair,
} from '../../shared/cryptoutil/cryptoUtil';
import {
  constructProofJWT,
  hasKeyPair,
  updateCredentialInformation,
  verifyCredentialData,
} from '../../shared/openId4VCI/Utils';
import VciClient from '../../shared/vciClient/VciClient';
import {displayType, issuerType} from './IssuersMachine';
import {setItem} from '../store';
import {API_CACHED_STORAGE_KEYS} from '../../shared/constants';
import {createCacheObject} from '../../shared/Utils';
import {VerificationResult} from '../../shared/vcjs/verifyCredential';
import {startIdPeruAuth} from '../../shared/idperu/IdPeruBridge';
import {idPeruSessionManager} from '../../shared/idperu/IdPeruSessionManager';
import {
  validateAuthCode,
  sanitizeErrorMessage,
} from '../../shared/idperu/IdPeruSecurity';
import {
  validateIdPeruUrl,
  formatUrlForDisplay,
  compareUrlParams,
} from '../../shared/idperu/IdPeruUrlValidator';

export const IssuersService = () => {
  return {
    isUserSignedAlready: () => async () => {
      return await Cloud.isSignedInAlready();
    },
    downloadIssuersList: async () => {
      const trustedIssuersList = await CACHED_API.fetchIssuers();
      return trustedIssuersList;
    },
    checkInternet: async () => await NetInfo.fetch(),
    downloadIssuerWellknown: async (context: any) => {
      const wellknownResponse =
        (await VciClient.getInstance().getIssuerMetadata(
          context.selectedIssuer.credential_issuer_host,
        )) as issuerType;
      if (wellknownResponse) {
        const wellknownCacheObject = createCacheObject(wellknownResponse);
        await setItem(
          API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(
            context.selectedIssuer.credential_issuer_host,
          ),
          wellknownCacheObject,
          '',
        );
      }

      return wellknownResponse;
    },
    getCredentialTypes: async (context: any) => {
      const credentialTypes: Array<{id: string; [key: string]: any}> = [];
      const selectedIssuer = context.selectedIssuer;

      const keys = Object.keys(
        selectedIssuer.credential_configurations_supported,
      );

      for (const key of keys) {
        if (selectedIssuer.credential_configurations_supported[key]) {
          credentialTypes.push({
            id: key,
            ...selectedIssuer.credential_configurations_supported[key],
          });
        }
      }

      if (credentialTypes.length === 0) {
        throw new Error(
          `No credential type found for issuer ${selectedIssuer.issuer_id}`,
        );
      }
      return credentialTypes;
    },

    downloadCredential: (context: any) => async (sendBack: any) => {
      const navigateToAuthView = (authorizationEndpoint: string) => {
        // Check if issuer uses IDPerú
        if (context.selectedIssuer?.use_idperu === true) {
          launchIdPeruAuth(context, authorizationEndpoint, sendBack);
          return;
        }

        // Default WebView flow
        let finalAuthEndpoint = authorizationEndpoint;
        // Add acr_values parameter if specified in issuer configuration
        if (context.selectedIssuer?.acr_values) {
          const url = new URL(authorizationEndpoint);
          url.searchParams.set('acr_values', context.selectedIssuer.acr_values);
          finalAuthEndpoint = url.toString();
        }
        sendBack({
          type: 'AUTH_ENDPOINT_RECEIVED',
          authEndpoint: finalAuthEndpoint,
        });
      };
      const getProofJwt = async (
        credentialIssuer: string,
        cNonce: string | null,
        proofSigningAlgosSupported: string[] | null,
      ) => {
        sendBack({
          type: 'PROOF_REQUEST',
          credentialIssuer: credentialIssuer,
          cNonce: cNonce,
          proofSigningAlgosSupported: proofSigningAlgosSupported,
        });
      };
      const getTokenResponse = (tokenRequest: object) => {
        // Add code_verifier from PKCE session if available
        const codeVerifier = idPeruSessionManager.getCodeVerifier();
        const enhancedTokenRequest = {
          ...tokenRequest,
          ...(codeVerifier && {codeVerifier}),
        };

        sendBack({
          type: 'TOKEN_REQUEST',
          tokenRequest: enhancedTokenRequest,
        });

        // Clear PKCE session after token request is sent
        if (codeVerifier) {
          idPeruSessionManager.clearSession();
        }
      };
      const {credential} =
        await VciClient.getInstance().requestCredentialFromTrustedIssuer(
          context.selectedIssuer.credential_issuer_host,
          context.selectedCredentialType.id,
          {
            clientId: context.selectedIssuer.client_id,
            redirectUri: context.selectedIssuer.redirect_uri,
          },
          getProofJwt,
          navigateToAuthView,
          getTokenResponse,
        );
      return updateCredentialInformation(context, credential);
    },
    sendTxCode: async (context: any) => {
      await VciClient.getInstance().sendTxCode(context.txCode);
    },

    sendConsentGiven: async () => {
      await VciClient.getInstance().sendIssuerConsent(true);
    },

    sendConsentNotGiven: async () => {
      await VciClient.getInstance().sendIssuerConsent(false);
    },

    checkIssuerIdInStoredTrustedIssuers: async (context: any) => {
      const {RNSecureKeystoreModule} = NativeModules;
      try {
        return await RNSecureKeystoreModule.hasAlias(
          context.credentialOfferCredentialIssuer,
        );
      } catch (error) {
        console.error(
          `Error while checking issuer ID in trusted issuers:`,
          error,
        );
        return false;
      }
    },
    addIssuerToTrustedIssuers: async (context: any) => {
      const {RNSecureKeystoreModule} = NativeModules;
      try {
        await RNSecureKeystoreModule.storeData(
          context.credentialOfferCredentialIssuer,
          'trusted',
        );
      } catch {
        console.error('Error updating issuer trust in keystore');
      }
    },
    downloadCredentialFromOffer: (context: any) => async (sendBack: any) => {
      const navigateToAuthView = (authorizationEndpoint: string) => {
        // Check if issuer uses IDPerú
        const issuer =
          context.selectedIssuer || context.credentialOfferCredentialIssuer;
        if (issuer?.use_idperu === true) {
          launchIdPeruAuth(context, authorizationEndpoint, sendBack);
          return;
        }

        // Default WebView flow
        let finalAuthEndpoint = authorizationEndpoint;
        // Add acr_values parameter if specified in issuer configuration
        if (issuer?.acr_values) {
          const url = new URL(authorizationEndpoint);
          url.searchParams.set('acr_values', issuer.acr_values);
          finalAuthEndpoint = url.toString();
        }
        sendBack({
          type: 'AUTH_ENDPOINT_RECEIVED',
          authEndpoint: finalAuthEndpoint,
        });
      };
      const getSignedProofJwt = async (
        credentialIssuer: string,
        cNonce: string | null,
        proofSigningAlgosSupported: string[] | null,
      ) => {
        sendBack({
          type: 'PROOF_REQUEST',
          cNonce: cNonce,
          issuer: credentialIssuer,
          proofSigningAlgosSupported: proofSigningAlgosSupported,
        });
      };

      const getTxCode = async (
        inputMode: string | undefined,
        description: string | undefined,
        length: number | undefined,
      ) => {
        sendBack({
          type: 'TX_CODE_REQUEST',
          inputMode: inputMode,
          description: description,
          length: length,
        });
      };

      const requesTrustIssuerConsent = async (
        credentialIssuer: string,
        issuerDisplay: object[],
      ) => {
        const issuerDisplayObject = issuerDisplay as displayType[];

        sendBack({
          type: 'TRUST_ISSUER_CONSENT_REQUEST',
          issuerDisplay: issuerDisplayObject,
          issuer: credentialIssuer,
        });
      };
      const getTokenResponse = (tokenRequest: object) => {
        // Add code_verifier from PKCE session if available
        const codeVerifier = idPeruSessionManager.getCodeVerifier();
        const enhancedTokenRequest = {
          ...tokenRequest,
          ...(codeVerifier && {codeVerifier}),
        };

        sendBack({
          type: 'TOKEN_REQUEST',
          tokenRequest: enhancedTokenRequest,
        });

        // Clear PKCE session after token request is sent
        if (codeVerifier) {
          idPeruSessionManager.clearSession();
        }
      };

      const credentialResponse =
        await VciClient.getInstance().requestCredentialByOffer(
          context.qrData,
          getTxCode,
          getSignedProofJwt,
          navigateToAuthView,
          getTokenResponse,
          requesTrustIssuerConsent,
        );
      return credentialResponse;
    },
    sendTokenRequest: async (context: any) => {
      const tokenRequestObject = context.tokenRequestObject;
      return await sendTokenRequest(
        tokenRequestObject,
        context.selectedIssuer?.token_endpoint,
      );
    },
    sendTokenResponse: async (context: any) => {
      const tokenResponse = context.tokenResponse;
      if (!tokenResponse) {
        throw new Error(
          'Could not send token response, tokenResponse is undefined or null',
        );
      }
      return await VciClient.getInstance().sendTokenResponse(
        JSON.stringify(tokenResponse),
      );
    },

    updateCredential: async (context: any) => {
      const credential = await updateCredentialInformation(
        context,
        context.credential,
      );
      return credential;
    },
    cacheIssuerWellknown: async (context: any) => {
      const credentialIssuer = context.credentialOfferCredentialIssuer;
      const issuerMetadata = (await VciClient.getInstance().getIssuerMetadata(
        credentialIssuer,
      )) as issuerType;
      if (issuerMetadata) {
        const wellknownCacheObject = createCacheObject(issuerMetadata);
        await setItem(
          API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(credentialIssuer),
          wellknownCacheObject,
          '',
        );
      }
      return issuerMetadata;
    },
    constructProof: async (context: any) => {
      const proofJWT = await constructProofJWT(
        context.publicKey,
        context.privateKey,
        context.credentialOfferCredentialIssuer,
        null,
        context.keyType,
        context.wellknownKeyTypes,
        true,
        context.cNonce,
      );
      await VciClient.getInstance().sendProof(proofJWT);
      return proofJWT;
    },
    constructAndSendProofForTrustedIssuers: async (context: any) => {
      const issuerMeta = context.selectedIssuer;
      const proofJWT = await constructProofJWT(
        context.publicKey,
        context.privateKey,
        context.selectedIssuer.credential_issuer_host,
        context.selectedIssuer.client_id,
        context.keyType,
        context.wellknownKeyTypes,
        false,
        context.cNonce,
      );
      await VciClient.getInstance().sendProof(proofJWT);
      return proofJWT;
    },

    getKeyOrderList: async () => {
      const {RNSecureKeystoreModule} = NativeModules;
      const keyOrder = JSON.parse(
        (await RNSecureKeystoreModule.getData('keyPreference'))[1],
      );
      return keyOrder;
    },

    generateKeyPair: async (context: any) => {
      const keypair = await generateKeyPair(context.keyType);
      return keypair;
    },

    getKeyPair: async (context: any) => {
      if (context.keyType === '') {
        throw new Error('key type not found');
      } else if (!!(await hasKeyPair(context.keyType))) {
        return await fetchKeyPair(context.keyType);
      }
    },

    getSelectedKey: async (context: any) => {
      return context.keyType;
    },

    verifyCredential: async (context: any): Promise<VerificationResult> => {
      const {
        isCredentialOfferFlow,
        verifiableCredential,
        selectedCredentialType,
      } = context;
      if (isCredentialOfferFlow) {
        const configurations = await getAllConfigurations();
        if (configurations.disableCredentialOfferVcVerification) {
          return {
            isVerified: true,
            verificationMessage: '',
            verificationErrorCode: '',
          };
        }
      }
      const verificationResult = await verifyCredentialData(
        verifiableCredential?.credential,
        selectedCredentialType.format,
      );
      if (!verificationResult.isVerified) {
        throw new Error(verificationResult.verificationErrorCode);
      }

      return verificationResult;
    },
  };
};

/**
 * Helper function to launch IDPerú authentication with PKCE
 * @param context Machine context
 * @param authorizationEndpoint Authorization endpoint URL
 * @param sendBack Callback to send events back to the machine
 */
async function launchIdPeruAuth(
  context: any,
  authorizationEndpoint: string,
  sendBack: any,
) {
  try {
    const issuer =
      context.selectedIssuer || context.credentialOfferCredentialIssuer;

    // Extract parameters from issuer configuration
    const clientId = issuer?.client_id || 'ab74ea27377a4830bf6905cd916';
    const redirectUri =
      issuer?.redirect_uri || 'io.mosip.residentapp.inji://oauthredirect';
    const scope = 'openid';
    const acrValues = issuer?.acr_values;
    const requiresQr = issuer?.idperu_requires_qr ?? false;

    // Generate PKCE code_verifier and code_challenge
    const {codeVerifier, codeChallenge} =
      await idPeruSessionManager.generatePKCE();

    // Log PKCE generation for verification
    if (__DEV__) {
      console.log('[IDPerú] PKCE Generated:', {
        codeVerifierLength: codeVerifier.length,
        codeChallengeLength: codeChallenge.length,
        codeChallengePreview: codeChallenge.substring(0, 20) + '...',
      });
    }

    let qrData: string;

    if (requiresQr) {
      // IDPerú requires QR data: fetch from authorization endpoint
      const authUrl = new URL(authorizationEndpoint);
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('scope', scope);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      if (acrValues) {
        authUrl.searchParams.set('acr_values', acrValues);
      }

      const finalUrl = authUrl.toString();

      // Log URL construction for verification
      if (__DEV__) {
        console.log('[IDPerú] Authorization URL (QR mode):', finalUrl);
        console.log('[IDPerú] URL Parameters:', {
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: scope,
          response_type: 'code',
          code_challenge: codeChallenge.substring(0, 20) + '...',
          code_challenge_method: 'S256',
          acr_values: acrValues || 'not set',
        });
      }

      // Fetch QR data from authorization endpoint
      const response = await fetch(authUrl.toString(), {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(
          `Failed to fetch QR data: ${response.status} ${response.statusText}`,
        );
      }

      const data = await response.json();
      qrData = data.qr_data || data.qrData || finalUrl;

      if (__DEV__) {
        console.log('[IDPerú] QR Data received:', {
          hasQrData: !!data.qr_data,
          hasQrDataAlt: !!data.qrData,
          qrDataLength: qrData.length,
          usingFallback: !data.qr_data && !data.qrData,
        });
      }
    } else {
      // IDPerú accepts full URL: construct URL with PKCE
      const authUrl = new URL(authorizationEndpoint);
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('scope', scope);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('code_challenge', codeChallenge);
      authUrl.searchParams.set('code_challenge_method', 'S256');
      if (acrValues) {
        authUrl.searchParams.set('acr_values', acrValues);
      }
      qrData = authUrl.toString();

      // Validate and log URL construction for verification
      const urlValidation = validateIdPeruUrl(qrData);
      const expectedParams = {
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: scope,
        response_type: 'code',
        code_challenge_method: 'S256',
        acr_values: acrValues || null, // null means optional
      };
      const paramComparison = compareUrlParams(qrData, expectedParams);

      if (__DEV__) {
        console.log('[IDPerú] ===== URL VERIFICATION =====');
        console.log('[IDPerú] Authorization URL (Direct mode):', qrData);
        console.log(
          '[IDPerú] URL (masked for display):',
          formatUrlForDisplay(qrData),
        );
        console.log('[IDPerú] URL Validation:', {
          isValid: urlValidation.isValid,
          errors: urlValidation.errors,
          warnings: urlValidation.warnings,
        });
        console.log('[IDPerú] Parameter Comparison:', {
          matches: paramComparison.matches,
          missing: paramComparison.missing,
          incorrect: paramComparison.incorrect,
          extra: paramComparison.extra,
        });
        console.log('[IDPerú] URL Parameters:', {
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: scope,
          response_type: 'code',
          code_challenge: codeChallenge.substring(0, 20) + '...',
          code_challenge_method: 'S256',
          acr_values: acrValues || 'not set',
        });
        console.log('[IDPerú] URL Breakdown:', {
          base: authorizationEndpoint,
          queryParams: Object.fromEntries(authUrl.searchParams),
        });
        console.log('[IDPerú] ============================');

        // Log errors if URL is invalid
        if (!urlValidation.isValid) {
          console.error(
            '[IDPerú] URL VALIDATION FAILED:',
            urlValidation.errors,
          );
        }
        if (!paramComparison.matches) {
          console.warn('[IDPerú] PARAMETER MISMATCH:', {
            missing: paramComparison.missing,
            incorrect: paramComparison.incorrect,
          });
        }
      }
    }

    // Get IDPerú configuration from issuer (with fallback defaults)
    const idPeruConfig = {
      androidPackage: issuer?.idperu_android_package || 'pe.gob.reniec.idperu',
      androidActivity:
        issuer?.idperu_android_activity || 'pe.gob.reniec.idperu.AuthActivity',
      androidInputKey: issuer?.idperu_android_input_key || 'auth_params',
      iosScheme: issuer?.idperu_ios_scheme,
      iosInputParam: issuer?.idperu_ios_input_param,
    };

    // Call IDPerú native module with new API
    const authCode = await startIdPeruAuth(qrData, idPeruConfig);

    // Validate authorization code
    if (!validateAuthCode(authCode)) {
      throw new Error('Invalid authorization code received from IDPerú');
    }

    // Send auth code to VCI client
    await VciClient.getInstance().sendAuthCode(authCode);
  } catch (error: any) {
    // Clean up PKCE session on error
    idPeruSessionManager.clearSession();

    const sanitizedError = sanitizeErrorMessage(error);
    console.error('IDPerú authentication error:', sanitizedError);

    // Send cancel event to machine
    sendBack({
      type: 'AUTH_CANCELED',
    });
  }
}

async function sendTokenRequest(
  tokenRequestObject: any,
  proxyTokenEndpoint: any = null,
) {
  if (proxyTokenEndpoint) {
    tokenRequestObject.tokenEndpoint = proxyTokenEndpoint;
  }
  if (!tokenRequestObject?.tokenEndpoint) {
    console.error('tokenEndpoint is not provided in tokenRequestObject');
    throw new Error('tokenEndpoint is required');
  }

  const formBody = new URLSearchParams();

  formBody.append('grant_type', tokenRequestObject.grantType);

  if (tokenRequestObject.authCode) {
    formBody.append('code', tokenRequestObject.authCode);
  }
  if (tokenRequestObject.preAuthCode) {
    formBody.append('pre-authorized_code', tokenRequestObject.preAuthCode);
  }
  if (tokenRequestObject.txCode) {
    formBody.append('tx_code', tokenRequestObject.txCode);
  }
  if (tokenRequestObject.clientId) {
    formBody.append('client_id', tokenRequestObject.clientId);
  }
  if (tokenRequestObject.redirectUri) {
    formBody.append('redirect_uri', tokenRequestObject.redirectUri);
  }
  if (tokenRequestObject.codeVerifier) {
    formBody.append('code_verifier', tokenRequestObject.codeVerifier);
  }
  const response = await fetch(tokenRequestObject.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: formBody.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(
      'Token request failed with status:',
      response.status,
      errorText,
    );
    throw new Error(`Token request failed: ${response.status} ${errorText}`);
  }
  const tokenResponse = await response.json();
  return tokenResponse;
}

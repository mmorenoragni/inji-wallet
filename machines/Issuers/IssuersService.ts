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
import {request} from '../../shared/request';

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
      console.log('[downloadIssuerWellknown] Starting wellknown download...');
      console.log(
        '[downloadIssuerWellknown] Credential issuer host:',
        context.selectedIssuer.credential_issuer_host,
      );
      console.log('[downloadIssuerWellknown] Full issuer config:', {
        issuer_id: context.selectedIssuer?.issuer_id,
        credential_issuer_host: context.selectedIssuer?.credential_issuer_host,
        authorization_servers: context.selectedIssuer?.authorization_servers,
        wellknown_endpoint: context.selectedIssuer?.wellknown_endpoint,
      });

      try {
        const wellknownResponse =
          (await VciClient.getInstance().getIssuerMetadata(
            context.selectedIssuer.credential_issuer_host,
          )) as issuerType;

        console.log(
          '[downloadIssuerWellknown] Wellknown response received successfully',
        );
        console.log(
          '[downloadIssuerWellknown] Authorization servers in response:',
          wellknownResponse?.authorization_servers,
        );
        console.log(
          '[downloadIssuerWellknown] Authorization endpoint:',
          wellknownResponse?.authorizationEndpoint,
        );
        console.log(
          '[downloadIssuerWellknown] Token endpoint:',
          wellknownResponse?.token_endpoint,
        );

        if (wellknownResponse) {
          const wellknownCacheObject = createCacheObject(wellknownResponse);
          await setItem(
            API_CACHED_STORAGE_KEYS.fetchIssuerWellknownConfig(
              context.selectedIssuer.credential_issuer_host,
            ),
            wellknownCacheObject,
            '',
          );
          console.log(
            '[downloadIssuerWellknown] Wellknown response cached successfully',
          );
        }

        return wellknownResponse;
      } catch (error: any) {
        console.error(
          '[downloadIssuerWellknown] ERROR during wellknown download:',
        );
        console.error(
          '[downloadIssuerWellknown] Error message:',
          error?.message,
        );
        console.error('[downloadIssuerWellknown] Error stack:', error?.stack);
        console.error(
          '[downloadIssuerWellknown] Full error object:',
          JSON.stringify(error, null, 2),
        );

        // Re-throw to maintain existing error handling
        throw error;
      }
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
      // Log initial context for debugging
      console.log('[downloadCredential] Starting credential download...');
      console.log('[downloadCredential] Issuer config:', {
        issuer_id: context.selectedIssuer?.issuer_id,
        credential_issuer_host: context.selectedIssuer?.credential_issuer_host,
        authorization_servers: context.selectedIssuer?.authorization_servers,
        authorizationEndpoint: context.selectedIssuer?.authorizationEndpoint,
        token_endpoint: context.selectedIssuer?.token_endpoint,
        use_idperu: context.selectedIssuer?.use_idperu,
      });
      console.log(
        '[downloadCredential] Selected credential type:',
        context.selectedCredentialType?.id,
      );

      const navigateToAuthView = (authorizationEndpoint: string) => {
        console.log(
          '[downloadCredential] navigateToAuthView called with:',
          authorizationEndpoint,
        );
        console.log('[downloadCredential] Checking IDPerú config:', {
          use_idperu: context.selectedIssuer?.use_idperu,
          idperu_android_package:
            context.selectedIssuer?.idperu_android_package,
          idperu_android_activity:
            context.selectedIssuer?.idperu_android_activity,
        });

        // Check if issuer uses IDPerú
        if (true) {
          console.log('[downloadCredential] Using IDPerú authentication flow');
          launchIdPeruAuth(context, authorizationEndpoint, sendBack);
          return;
        }

        // Default WebView flow
        console.log(
          '[downloadCredential] Using WebView authentication flow (use_idperu is not true)',
        );
        let finalAuthEndpoint = authorizationEndpoint;
        // Add acr_values parameter if specified in issuer configuration
        if (context.selectedIssuer?.acr_values) {
          const url = new URL(authorizationEndpoint);
          url.searchParams.set('acr_values', context.selectedIssuer.acr_values);
          finalAuthEndpoint = url.toString();
          console.log(
            '[downloadCredential] Added acr_values, final endpoint:',
            finalAuthEndpoint,
          );
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
        console.log('[downloadCredential] getProofJwt called:', {
          credentialIssuer,
          cNonce,
          proofSigningAlgosSupported,
        });
        sendBack({
          type: 'PROOF_REQUEST',
          credentialIssuer: credentialIssuer,
          cNonce: cNonce,
          proofSigningAlgosSupported: proofSigningAlgosSupported,
        });
      };

      const getTokenResponse = (tokenRequest: object) => {
        console.log(
          '[downloadCredential] getTokenResponse called with request:',
          tokenRequest,
        );

        // Add code_verifier from PKCE session if available
        const codeVerifier = idPeruSessionManager.getCodeVerifier();
        const enhancedTokenRequest = {
          ...tokenRequest,
          ...(codeVerifier && {codeVerifier}),
        };

        console.log(
          '[downloadCredential] Enhanced token request (code_verifier added):',
          {
            ...enhancedTokenRequest,
            codeVerifier: codeVerifier ? 'present' : 'not present',
          },
        );

        sendBack({
          type: 'TOKEN_REQUEST',
          tokenRequest: enhancedTokenRequest,
        });

        // Clear PKCE session after token request is sent
        if (codeVerifier) {
          idPeruSessionManager.clearSession();
          console.log('[downloadCredential] PKCE session cleared');
        }
      };

      try {
        console.log(
          '[downloadCredential] Calling VciClient.requestCredentialFromTrustedIssuer...',
        );
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
        console.log('[downloadCredential] Credential received successfully');
        return updateCredentialInformation(context, credential);
      } catch (error: any) {
        console.error('[downloadCredential] ERROR during credential download:');
        console.error('[downloadCredential] Error message:', error?.message);
        console.error('[downloadCredential] Error stack:', error?.stack);
        console.error(
          '[downloadCredential] Full error object:',
          JSON.stringify(error, null, 2),
        );

        // Re-throw to maintain existing error handling
        throw error;
      }
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
      console.log(
        '[IDPerú] downloadCredentialFromOffer Starting credential download from offer...',
      );
      console.log(
        '[IDPerú] downloadCredentialFromOffer Selected Issuer:',
        context.selectedIssuer,
      );
      console.log('[IDPerú] downloadCredentialFromOffer Context:', context);
      console.log('[IDPerú] downloadCredentialFromOffer Send Back:', sendBack);
      console.log(
        '[IDPerú] downloadCredentialFromOffer QR Data:',
        context.qrData,
      );
      const navigateToAuthView = (authorizationEndpoint: string) => {
        // Check if issuer uses IDPerú
        const issuer =
          context.selectedIssuer || context.credentialOfferCredentialIssuer;
        if (true) {
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
    console.log('[IDPerú] launchIdPeruAuth called with:', {
      authorizationEndpoint: authorizationEndpoint,
      context: context,
    });
    const issuer =
      context.selectedIssuer || context.credentialOfferCredentialIssuer;
    console.log('[IDPerú] Issuer:', issuer);
    // Extract parameters from issuer configuration
    const clientId = issuer?.client_id || 'ab74ea27377a4830bf6905cd916';
    const redirectUri = issuer?.redirect_uri || 'io.mosip.residentapp.inji';
    console.log('[IDPerú] Client ID:', clientId);
    console.log('[IDPerú] Redirect URI:', redirectUri);
    const scope = 'openid';
    // ACR values is REQUIRED for RENIEC/IDPerú - default to pki_dnie if not specified
    const acrValues = issuer?.acr_values || 'pki_dnie';
    const requiresQr = true;
    console.log('[IDPerú] ACR Values:', acrValues);
    console.log('[IDPerú] Requires QR:', requiresQr);

    if (__DEV__ && !issuer?.acr_values) {
      console.log('[IDPerú] Using hardcoded fallback acr_values: pki_dnie');
    }
    console.log('[IDPerú] Generating PKCE code_verifier and code_challenge');
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
      // IDPerú requires QR data: fetch from Mimoto bc-authorize endpoint
      const bcAuthorizeEndpoint = '/v1/mimoto/bc-authorize';

      // Log request for verification
      if (__DEV__) {
        console.log(
          '[IDPerú] ===== FETCHING SESSION FROM MIMOTO BC-AUTHORIZE =====',
        );
        console.log('[IDPerú] Endpoint:', bcAuthorizeEndpoint);
        console.log('[IDPerú] Making GET request to fetch auth_req_id...');
      }

      // Fetch QR data from Mimoto bc-authorize endpoint
      const data = await request('GET', bcAuthorizeEndpoint);

      console.log('[IDPerú] Response data:', data);

      // Extract auth_req_id from response
      if (!data.auth_req_id) {
        throw new Error('Missing auth_req_id in bc-authorize response');
      }

      qrData = data.auth_req_id;

      console.log('[IDPerú] Auth Request ID:', qrData);
      console.log('[IDPerú] Expires in:', data.expires_in, 'seconds');
      console.log('[IDPerú] Interval:', data.interval, 'seconds');
      console.log('[IDPerú] Code Challenge:', codeChallenge);
      console.log('[IDPerú] Code Verifier:', codeVerifier);
      console.log('[IDPerú] Scope:', scope);
      console.log('[IDPerú] ACR Values:', acrValues);
      console.log('[IDPerú] Requires QR:', requiresQr);
      console.log('[IDPerú] Client ID:', clientId);

      if (__DEV__) {
        console.log('[IDPerú] Response from bc-authorize endpoint:', data);
        console.log('[IDPerú] Session data received:', {
          auth_req_id: qrData,
          expires_in: data.expires_in,
          interval: data.interval,
          authReqIdLength: qrData.length,
          authReqIdPreview: qrData.substring(0, 50) + '...',
          startsWithReniecIdaas: qrData.startsWith('RENIEC_IDAAS.'),
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
      // ACR values is REQUIRED for RENIEC/IDPerú (hardcoded fallback to pki_dnie)
      authUrl.searchParams.set('acr_values', acrValues);
      qrData = authUrl.toString();

      // Validate and log URL construction for verification
      const urlValidation = validateIdPeruUrl(qrData);
      const expectedParams = {
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: scope,
        response_type: 'code',
        code_challenge_method: 'S256',
        acr_values: acrValues || 'pki_dnie', // null means optional
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
      androidPackage:
        issuer?.idperu_android_package || 'pe.gob.reniec.pki.reniecidaas2',
      androidActivity:
        issuer?.idperu_android_activity ||
        'pe.gob.reniec.feature.gateway.AppGatewayActivity',
      androidInputKey: issuer?.idperu_android_input_key || 'code',
      iosScheme: issuer?.idperu_ios_scheme,
      iosInputParam: issuer?.idperu_ios_input_param,
    };

    if (__DEV__) {
      console.log('[IDPerú] ===== LAUNCHING IDPerú APP =====');
      console.log('[IDPerú] Session data to pass:', {
        dataType: qrData.startsWith('RENIEC_IDAAS.')
          ? 'codePkiFlow'
          : qrData.startsWith('http')
          ? 'URL'
          : 'unknown',
        dataLength: qrData.length,
        dataPreview: qrData.substring(0, 60) + '...',
      });
      console.log('[IDPerú] Config:', idPeruConfig);
      console.log('[IDPerú] Calling startIdPeruAuth...');
    }
    console.log('[IDPerú] qrData:', qrData);
    // Call IDPerú native module with new API
    const authCode = await startIdPeruAuth(qrData, idPeruConfig);
    console.log('[IDPerú] authCode:', authCode);
    if (__DEV__) {
      console.log('[IDPerú] ===== AUTHORIZATION CODE RECEIVED =====');
      console.log('[IDPerú] Auth code length:', authCode?.length);
      console.log(
        '[IDPerú] Auth code preview:',
        authCode?.substring(0, 20) + '...',
      );
    }

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

/**
 * useSmartLinkDevice - Unified QR code scanner for device linking
 *
 * This hook handles both:
 * 1. Terminal/Machine Connection (happy auth login): happier://terminal?key=...&server=...
 * 2. Account Connection (device linking): happier:///account?...
 *
 * Shows distinct confirmation modals with visual cues before processing.
 */

import * as React from 'react';
import { Platform, View, Text as RNText } from 'react-native';
import { CameraView } from 'expo-camera';
import { Ionicons } from '@expo/vector-icons';
import { router } from 'expo-router';
import { useAuth } from '@/auth/context/AuthContext';
import { decodeBase64 } from '@/encryption/base64';
import { encryptBox } from '@/encryption/libsodium';
import { authAccountApprove } from '@/auth/flows/accountApprove';
import { authApprove } from '@/auth/flows/approve';
import { buildTerminalResponseV1, buildTerminalResponseV2 } from '@/auth/terminal/terminalProvisioning';
import { useCheckScannerPermissions } from '@/hooks/ui/useCheckCameraPermissions';
import { useConnectTerminal } from '@/hooks/session/useConnectTerminal';
import { Modal } from '@/modal';
import { t } from '@/text';
import { isLegacyAuthCredentials, type AuthCredentials } from '@/auth/storage/tokenStorage';
import { sync } from '@/sync/sync';
import { storage } from '@/sync/domains/state/storageStore';
import { getActiveServerUrl } from '@/sync/domains/server/serverProfiles';
import { normalizeServerUrl, upsertActivateAndSwitchServer } from '@/sync/domains/server/activeServerSwitch';
import { clearPendingTerminalConnect, setPendingTerminalConnect } from '@/sync/domains/pending/pendingTerminalConnect';
import { parseTerminalConnectUrl } from '@/utils/path/terminalConnectUrl';
import { TokenStorage } from '@/auth/storage/tokenStorage';

export type LinkDeviceType = 'terminal' | 'account';

interface ParsedQrResult {
    type: LinkDeviceType;
    url: string;
    machineName?: string;  // Extracted from terminal connection if available
}

interface UseSmartLinkDeviceOptions {
    onSuccess?: () => void;
    onError?: (error: any) => void;
}

function getQrCodeType(url: string): ParsedQrResult | null {
    if (url.startsWith('happier://terminal?')) {
        return { type: 'terminal', url };
    }
    if (url.startsWith('happier:///account?')) {
        return { type: 'account', url };
    }
    return null;
}

export function useSmartLinkDevice(options?: UseSmartLinkDeviceOptions) {
    const auth = useAuth();
    const [isLoading, setIsLoading] = React.useState(false);
    const checkScannerPermissions = useCheckScannerPermissions();
    const isProcessingRef = React.useRef(false);
    const connectTerminal = useConnectTerminal();

    /**
     * Process account connection (linking a new mobile device)
     */
    const processAccountConnection = React.useCallback(async (url: string): Promise<boolean> => {
        if (!url.startsWith('happier:///account?')) {
            return false;
        }

        setIsLoading(true);
        try {
            const tail = url.slice('happier:///account?'.length);
            const publicKey = decodeBase64(tail, 'base64url');
            const creds = auth.credentials!;
            const secretKey = isLegacyAuthCredentials(creds)
                ? decodeBase64(creds.secret, 'base64url')
                : decodeBase64(creds.encryption.machineKey, 'base64');
            const response = encryptBox(secretKey, publicKey);

            await authAccountApprove(auth.credentials!.token, publicKey, response);

            Modal.alert(t('common.success'), t('modals.deviceLinkedSuccessfully'), [
                {
                    text: t('common.ok'),
                    onPress: () => options?.onSuccess?.()
                }
            ]);
            return true;
        } catch (e) {
            console.error(e);
            Modal.alert(t('common.error'), t('modals.failedToLinkDevice'), [{ text: t('common.ok') }]);
            options?.onError?.(e);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [auth.credentials, options]);

    /**
     * Process terminal connection (happy auth login)
     * This is similar to useConnectTerminal but without the initial QR scan
     */
    const processTerminalConnection = React.useCallback(async (url: string): Promise<boolean> => {
        const parsed = parseTerminalConnectUrl(url);
        if (!parsed) {
            Modal.alert(t('common.error'), t('modals.invalidAuthUrl'), [{ text: t('common.ok') }]);
            return false;
        }

        setIsLoading(true);
        try {
            let activeCredentials: AuthCredentials | null = auth.credentials;

            if (parsed.serverUrl) {
                const targetServerUrl = normalizeServerUrl(parsed.serverUrl);
                const currentServerUrl = normalizeServerUrl(getActiveServerUrl());
                if (targetServerUrl && currentServerUrl !== targetServerUrl) {
                    setPendingTerminalConnect({ publicKeyB64Url: parsed.publicKeyB64Url, serverUrl: targetServerUrl });
                    await upsertActivateAndSwitchServer({
                        serverUrl: targetServerUrl,
                        source: 'url',
                        scope: 'device',
                        refreshAuth: auth.refreshFromActiveServer,
                    });
                    activeCredentials = await TokenStorage.getCredentials();
                }
            }

            if (!activeCredentials) {
                activeCredentials = await TokenStorage.getCredentials();
            }

            if (!activeCredentials) {
                setPendingTerminalConnect({
                    publicKeyB64Url: parsed.publicKeyB64Url,
                    serverUrl: normalizeServerUrl(parsed.serverUrl ?? '') || getActiveServerUrl(),
                });
                await Modal.alert(t('terminal.connectTerminal'), t('modals.pleaseSignInFirst'), [
                    { text: t('common.continue') },
                ]);
                router.replace('/');
                return false;
            }

            const publicKey = decodeBase64(parsed.publicKeyB64Url, 'base64url');

            const allowLegacySecretExportEnabled = Boolean(
                storage.getState().settings?.terminalConnectLegacySecretExportEnabled,
            );

            const contentPrivateKey = sync.encryption?.getContentPrivateKey
                ? sync.encryption.getContentPrivateKey()
                : new Uint8Array();

            const responseV2 = buildTerminalResponseV2({
                contentPrivateKey,
                terminalEphemeralPublicKey: publicKey,
            });

            const responseV1 =
                allowLegacySecretExportEnabled && isLegacyAuthCredentials(activeCredentials)
                    ? () =>
                        buildTerminalResponseV1({
                            legacySecretB64Url: activeCredentials.secret,
                            terminalEphemeralPublicKey: publicKey,
                        })
                    : new Uint8Array();

            const approvalResult = await authApprove(activeCredentials.token, publicKey, responseV1, responseV2);

            clearPendingTerminalConnect();

            if (approvalResult === 'approved') {
                Modal.alert(t('common.success'), t('modals.terminalConnectedSuccessfully'), [
                    {
                        text: t('common.ok'),
                        onPress: () => options?.onSuccess?.()
                    }
                ]);
                return true;
            }

            if (approvalResult === 'already_authorized') {
                Modal.alert(
                    t('modals.terminalAlreadyConnected'),
                    t('modals.terminalConnectionAlreadyUsedDescription'),
                    [{ text: t('common.ok') }]
                );
                return false;
            }

            if (approvalResult === 'not_found') {
                Modal.alert(
                    t('modals.authRequestExpired'),
                    t('modals.authRequestExpiredDescription'),
                    [{ text: t('common.ok') }]
                );
                return false;
            }

            Modal.alert(t('common.error'), t('modals.failedToConnectTerminal'), [{ text: t('common.ok') }]);
            return false;
        } catch (e) {
            console.error(e);
            Modal.alert(t('common.error'), t('modals.failedToConnectTerminal'), [{ text: t('common.ok') }]);
            options?.onError?.(e);
            return false;
        } finally {
            setIsLoading(false);
        }
    }, [auth.credentials, auth.refreshFromActiveServer, options]);

    /**
     * Show confirmation modal before processing
     */
    const showConfirmationAndProcess = React.useCallback(async (qrResult: ParsedQrResult) => {
        const { type, url } = qrResult;

        if (type === 'terminal') {
            // Show machine connection confirmation
            Modal.confirmCustom(
                t('modals.addingNewMachine'),
                t('modals.addingNewMachineDescription'),
                {
                    confirmText: t('common.continue'),
                    cancelText: t('common.cancel'),
                    icon: (
                        <View style={{ alignItems: 'center', marginBottom: 12 }}>
                            <View style={{
                                width: 64,
                                height: 64,
                                borderRadius: 32,
                                backgroundColor: '#007AFF',
                                alignItems: 'center',
                                justifyContent: 'center',
                            }}>
                                <Ionicons name="desktop-outline" size={32} color="#FFFFFF" />
                            </View>
                        </View>
                    ),
                    onConfirm: async () => {
                        await processTerminalConnection(url);
                    }
                }
            );
        } else {
            // Show account connection confirmation
            Modal.confirmCustom(
                t('modals.linkNewDeviceTitle'),
                t('modals.linkNewDeviceConfirmation'),
                {
                    confirmText: t('common.continue'),
                    cancelText: t('common.cancel'),
                    icon: (
                        <View style={{ alignItems: 'center', marginBottom: 12 }}>
                            <View style={{
                                width: 64,
                                height: 64,
                                borderRadius: 32,
                                backgroundColor: '#34C759',
                                alignItems: 'center',
                                justifyContent: 'center',
                            }}>
                                <Ionicons name="person-outline" size={32} color="#FFFFFF" />
                            </View>
                        </View>
                    ),
                    onConfirm: async () => {
                        await processAccountConnection(url);
                    }
                }
            );
        }
    }, [processTerminalConnection, processAccountConnection]);

    /**
     * Main entry point - launches QR scanner
     */
    const linkNewDevice = React.useCallback(async () => {
        if (await checkScannerPermissions()) {
            CameraView.launchScanner({
                barcodeTypes: ['qr']
            });
        } else {
            Modal.alert(t('common.error'), t('modals.cameraPermissionsRequiredToScanQr'), [{ text: t('common.ok') }]);
        }
    }, [checkScannerPermissions]);

    /**
     * Manual URL entry (for testing)
     */
    const linkWithUrl = React.useCallback(async (url: string) => {
        const qrResult = getQrCodeType(url);
        if (!qrResult) {
            Modal.alert(t('common.error'), t('modals.invalidAuthUrl'), [{ text: t('common.ok') }]);
            return;
        }
        await showConfirmationAndProcess(qrResult);
    }, [showConfirmationAndProcess]);

    // Set up barcode scanner listener
    React.useEffect(() => {
        if (CameraView.isModernBarcodeScannerAvailable) {
            const subscription = CameraView.onModernBarcodeScanned(async (event) => {
                const qrResult = getQrCodeType(event.data);
                if (!qrResult) {
                    return; // Not a QR code we handle
                }

                if (isProcessingRef.current) {
                    return;
                }
                isProcessingRef.current = true;
                try {
                    // Dismiss scanner on Android is called automatically when barcode is scanned
                    if (Platform.OS === 'ios') {
                        await CameraView.dismissScanner().catch(() => {});
                    }
                    await showConfirmationAndProcess(qrResult);
                } finally {
                    isProcessingRef.current = false;
                }
            });
            return () => {
                subscription.remove();
                if (Platform.OS === 'ios') {
                    void CameraView.dismissScanner().catch(() => {});
                }
            };
        }
    }, [showConfirmationAndProcess]);

    return {
        linkNewDevice,
        linkWithUrl,
        isLoading,
    };
}

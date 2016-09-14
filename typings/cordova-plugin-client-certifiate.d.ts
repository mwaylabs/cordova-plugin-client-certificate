interface CordovaClientCertificatePlugin {
    registerAuthenticationCertificate(certificatePath: string, certificatePassword: string, successCallback: (message: string) => void, errorCallback: (error: string) => void);
    validateSslChain(validate: any, successCallback: (success: string) => void, errorCallback: (error: string) => void);
}

declare var clientCertificate: CordovaClientCertificatePlugin;
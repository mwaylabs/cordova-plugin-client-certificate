/*global cordova, module*/

module.exports = {
    registerAuthenticationCertificate: function (certificatePath, certificatePassword, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "ClientCertificate", "registerAuthenticationCertificate", [certificatePath, certificatePassword]);
    },
    validateSslChain: function (validate, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "ClientCertificate", "validateSslChain", [validate]);
    }
};
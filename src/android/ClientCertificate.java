package org.apache.cordova.plugin.clientcert;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.util.Log;
import android.widget.Toast;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.ICordovaClientCertRequest;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.json.JSONObject;
import org.json.JSONArray;
import org.json.JSONException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Arrays;
import java.util.Enumeration;
import java.io.FileInputStream;
import java.io.InputStream;

@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificate extends CordovaPlugin {

    private String p12path = "";
    private String p12password = "";

    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");

            InputStream astream = cordova.getActivity().getApplicationContext().getAssets().open(p12path);
            keystore.load(astream, p12password.toCharArray());
            astream.close();
            Enumeration e = keystore.aliases();
            if (e.hasMoreElements()) {
                String ealias = (String) e.nextElement();
                PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12password.toCharArray());
                java.security.cert.Certificate[]  chain = keystore.getCertificateChain(ealias);
                X509Certificate[] certs = Arrays.copyOf(chain, chain.length, X509Certificate[].class);
                request.proceed(key,certs);
            } else {
                request.ignore();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            request.ignore();
        }
        return true;
    }

    @Override
    public boolean execute(String action, JSONArray a, CallbackContext c) throws JSONException {
        if (action.equals("registerAuthenticationCertificate")) {
            p12path = a.getString(0);
            p12password = a.getString(1);
            return true;
        }
        return false;
    }
}

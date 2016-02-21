
package org.apache.cordova.plugin.clientcertificate;

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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;


@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ClientCertificate extends CordovaPlugin {


    public String p12path = "";
    public String p12password = "";


    @Override
    public Boolean shouldAllowBridgeAccess(String url) {
        return super.shouldAllowBridgeAccess(url);
    }


    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    @Override
    public boolean onReceivedClientCertRequest(CordovaWebView view, ICordovaClientCertRequest request) {
      try {
                KeyStore keystore = KeyStore.getInstance("PKCS12");
               
                InputStream astream = getAssets().open(p12path);
                keystore.load(astream, p12password.toCharArray());
                astream.close();
                Enumeration e = keystore.aliases();
                if (e.hasMoreElements()) {
                    String ealias = (String) e.nextElement();
                    PrivateKey key = (PrivateKey) keystore.getKey(ealias, p12password.toCharArray());
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    InputStream bstream = getAssets().open(p12path);
                    Collection c = cf.generateCertificates(bstream);
                    bstream.close();
                    X509Certificate[] certs = (X509Certificate[])(c.toArray(new X509Certificate[c.size()]));
                    request.proceed(key,certs);
                } else
                {
                    request.ignore();
                }

            } catch (Exception ex)
            {
                request.ignore();
            }
        return true;
    }

    @Override
    public boolean execute(String action, JSONArray a, CallbackContext c) throws JSONException {
        if (action.equals("register"))
        {
            p12path = "www/" + a.getString(0);
            p12password = a.getString(1);
            return true;
        }
        return false;
    }


}
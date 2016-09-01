# Cordova Client Certificate Plugin

Plugin that uses a client certificate for authentication.

## Using
Clone the plugin

    $ git clone https://github.com/mwaylabs/cordova-plugin-client-certificate.git

Create a new Cordova Project

    $ cordova create hello com.example.helloapp Hello
    
Install the plugin

    $ cd hello
    $ cordova plugin add ../cordova-plugin-client-certificate
    

Copy a client certificate to your www/ folder.

Edit `www/js/index.js` and add the following code inside `onDeviceReady`

```js
    var success = function(message) {
        alert(message);
    }

    var failure = function(error) {
        alert("Error:" + error);
    }

    clientCertificate.registerAuthenticationCertificate("certfilePath/cert.p12", "s3cr37", success, failure);
```

Install iOS platform

    cordova platform add ios
    
Run the code

    cordova run 

## More Info

For more information on setting up Cordova see [the documentation](http://cordova.apache.org/docs/en/4.0.0/guide_cli_index.md.html#The%20Command-Line%20Interface)

For more info on plugins see the [Plugin Development Guide](http://cordova.apache.org/docs/en/4.0.0/guide_hybrid_plugins_index.md.html#Plugin%20Development%20Guide)

/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#include <sys/types.h>
#include <sys/sysctl.h>
#include "TargetConditionals.h"

#import <Cordova/CDV.h>
#import "ClientCertificate.h"

@interface ClientCertificate ()
{
    NSString* certificatePath;
    NSString* certificatePassword;
}
@end

@implementation ClientCertificate

- (void)register:(CDVInvokedUrlCommand*)command
{
    NSString* certPath = [command argumentAtIndex:0];
    NSString* password = [command argumentAtIndex:1];

    //check certificate path
    NSString *path = [[[NSBundle mainBundle] resourcePath] stringByAppendingFormat:@"/www/%@", certPath];
    if(![[NSFileManager defaultManager] fileExistsAtPath:path]) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:[NSString stringWithFormat:@"certificate file not found: %@", path]];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }
    
    //check certificate and password
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    OSStatus status = extractIdentityAndTrust(path, password, &myIdentity, &myTrust);
    if(status != noErr) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"reading certificate failed."];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }
    
    certificatePath = path;
    certificatePassword = password;
    
    //resgister custom protocol
    [CustomHTTPProtocol setDelegate:self];
    [CustomHTTPProtocol start];
    
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];

    
}

- (BOOL)customHTTPProtocol:(CustomHTTPProtocol *)protocol canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    NSLog(@"canAuthenticateAgainstProtectionSpace: %@", protectionSpace.authenticationMethod);
    
    if ([protectionSpace authenticationMethod] == NSURLAuthenticationMethodServerTrust) {
        return YES;
    } else if ([protectionSpace authenticationMethod] == NSURLAuthenticationMethodClientCertificate) {
        return YES;
    }
    
    return NO;
}

- (void)customHTTPProtocol:(CustomHTTPProtocol *)protocol didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    if([challenge previousFailureCount] == 0) {
        
        NSURLCredential *credential = nil;
        
        NSURLProtectionSpace *protectionSpace = [challenge protectionSpace];
        NSString *authMethod = [protectionSpace authenticationMethod];
        if(authMethod == NSURLAuthenticationMethodServerTrust ) {
            credential = [NSURLCredential credentialForTrust:[protectionSpace serverTrust]];
        }
        
        else if(authMethod == NSURLAuthenticationMethodClientCertificate ) {
            OSStatus status = noErr;
            SecIdentityRef myIdentity;
            SecTrustRef myTrust;
            status = extractIdentityAndTrust(certificatePath, certificatePassword, &myIdentity, &myTrust);
            
            SecTrustResultType trustResult;
            
            if (status == noErr) {
                status = SecTrustEvaluate(myTrust, &trustResult);
            }
            
            SecCertificateRef myCertificate;
            SecIdentityCopyCertificate(myIdentity, &myCertificate);
            const void *certs[] = { myCertificate };
            CFArrayRef certsArray = CFArrayCreate(NULL, certs, 1, NULL);
            credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];

        }
        
        [protocol resolveAuthenticationChallenge:challenge withCredential:credential];
        
    }
}

OSStatus extractIdentityAndTrust(NSString *certPath, NSString *pwd, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:certPath];
    CFDataRef inPKCS12Data = (__bridge CFDataRef)PKCS12Data;
    CFStringRef passwordRef = (__bridge CFStringRef)pwd; // Password for Certificate which client have given
    
    const void *keys[] =   { kSecImportExportPassphrase };
    const void *values[] = { passwordRef };
    
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex (items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemIdentity);
        
        *identity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue (myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;
    }
    
    if (optionsDictionary) {
        CFRelease(optionsDictionary);
    }
    
    return securityError;
}



@end

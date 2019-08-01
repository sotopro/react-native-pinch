

#import "RNPinchDelegate.h"
#import "RNPinchException.h"


@implementation RNPinchDelegate

- (id)init {
    if (self = [super init]) {
        _mutualAuthCert = nil;
        _mutualAuthPassword = @"";
        _pinningCerts = @[];
    }
    return self;
}

- (void)setMutualAuthCert:(NSString *)cert andPassword:(NSString *)password{
    _mutualAuthCert = [[NSData alloc] initWithBase64EncodedString:cert options:NSDataBase64DecodingIgnoreUnknownCharacters];
    _mutualAuthPassword = password;
}

- (void) setSSLPinningCert:(NSString *)cert{
    _pinningCerts =  @[cert];
}

- (void) setSSLPinningCerts:(NSArray<NSString *> *)certs{
    _pinningCerts = certs;
}

- (NSArray *)pinnedCertificateData {
    NSMutableArray *localCertData = [NSMutableArray array];
    for (NSString* certName in _pinningCerts) {
        NSString *cerPath = [[NSBundle mainBundle] pathForResource:certName ofType:@"cer"];
        if(cerPath!=nil){
            NSData *certData = [NSData dataWithContentsOfFile:cerPath];
            [localCertData addObject:certData];
            
        }else{
            NSData *certData = [[NSData alloc] initWithBase64EncodedString:certName options:NSDataBase64DecodingIgnoreUnknownCharacters];
            if (certData != nil) {
                [localCertData addObject:certData];
            }
        }
    }
    
    NSMutableArray *pinnedCertificates = [NSMutableArray array];
    @try {
        for (NSData *certificateData in localCertData) {
            if(certificateData!=nil){
                [pinnedCertificates addObject:(__bridge_transfer id)SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certificateData)];
            }
        }
    }
    @catch(NSException *e) {
        NSLog(@"pinnedCertificates %@",[e reason]);
    }
    return pinnedCertificates;
}

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler {
    
    if (challenge.previousFailureCount > 0) {
        
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        
    } else if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        
        
        NSString *domain = challenge.protectionSpace.host;
        SecTrustRef serverTrust = [[challenge protectionSpace] serverTrust];
        
        NSArray *policies = @[(__bridge_transfer id)SecPolicyCreateSSL(true, (__bridge CFStringRef)domain)];
         
        SecTrustSetPolicies(serverTrust, (__bridge CFArrayRef)policies);
        SecTrustSetNetworkFetchAllowed(serverTrust, YES);
        
        // setup
        SecTrustSetAnchorCertificates(serverTrust, (__bridge CFArrayRef)self.pinnedCertificateData);
        SecTrustSetAnchorCertificatesOnly(serverTrust, YES);
        SecTrustResultType result;
        
        // evaluate
        OSStatus errorCode = SecTrustEvaluate(serverTrust, &result);
        
      
        
        BOOL evaluatesAsTrusted = (result == kSecTrustResultUnspecified || result == kSecTrustResultProceed);
        
        if (errorCode == errSecSuccess && evaluatesAsTrusted) {
            NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        } else {
            completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, NULL);
        }
        
    } else if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
        
        @try {
            NSURLCredential * credential = [self socketTrustSetup];
            completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        }
        @catch(NSException *e) {
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        }
        
    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
    
    
   
}

- (NSURLCredential *)socketTrustSetup {
    
    CFStringRef password = (__bridge CFStringRef)_mutualAuthPassword;
    CFDataRef cert = (__bridge CFDataRef)_mutualAuthCert;
    
    if(cert==nil){
        NSException * _exception = [[NSException alloc] initWithName:@"Cert is empty or cant be decoded" reason:@"Cert is empty or cant be decoded." userInfo:NULL];
        @throw _exception;
    }
    
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    CFArrayRef p12Items;
    OSStatus result = SecPKCS12Import(cert, optionsDictionary, &p12Items);
    
    if (result == noErr) {
        
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(p12Items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        
        SecCertificateRef certRef;
        SecIdentityCopyCertificate(identityApp, &certRef);
        
        SecCertificateRef certArray[1] = { certRef };
        CFArrayRef myCerts = CFArrayCreate(NULL, (void*)certArray, 1, NULL);
        CFRelease(certRef);
        
        NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identityApp certificates:(__bridge NSArray *)myCerts persistence:NSURLCredentialPersistencePermanent];
        CFRelease(myCerts);
        
        return credential;
        
    } else if (result == errSecAuthFailed) {
        
       NSException * _exception = [[NSException alloc] initWithName:@"PKCS12 key store mac invalid" reason:@"PKCS12 key store mac invalid - wrong password or corrupted file." userInfo:NULL];
        
        @throw _exception;
        
    } else if (result == errSecDecode) {
        
         NSException * _exception = [[NSException alloc] initWithName:@"PKCS12 key store mac invalid" reason:@"PKCS12 key store mac invalid - unable to decode the provided data." userInfo:NULL];
        
        @throw _exception;
        
    }
    
    return 0;
    
}

@end

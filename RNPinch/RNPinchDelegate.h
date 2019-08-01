

#import <Foundation/Foundation.h>


@interface RNPinchDelegate : NSObject<NSURLSessionDelegate> {
    
    NSArray<NSString *> *_pinningCerts;
    NSData * _mutualAuthCert;
    NSString * _mutualAuthPassword;
    
}

- (id)init;

- (void)setMutualAuthCert:(NSString *)cert andPassword: (NSString *) password;
- (void)setSSLPinningCert:(NSString *)cert;
- (void)setSSLPinningCerts:(NSArray<NSString *> *)certs;


@end


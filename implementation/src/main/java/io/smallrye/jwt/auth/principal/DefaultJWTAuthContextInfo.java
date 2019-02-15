/**
 *
 *   Copyright 2018 Red Hat, Inc, and individual contributors.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
package io.smallrye.jwt.auth.principal;


import java.security.interfaces.RSAPublicKey;

import io.smallrye.jwt.KeyUtils;

/**
 * The public key and expected issuer needed to validate a token.
 */
public class DefaultJWTAuthContextInfo {
    // Standard MP-JWT properties
    public static final String MP_JWT_VERIY_PUBLIC_KEY = "mp.jwt.verify.publickey"; 
    public static final String MP_JWT_VERIY_PUBLIC_KEY_LOCATION = "mp.jwt.verify.publickey.location";
    public static final String MP_JWT_VERIY_PUBLIC_ISSUER = "mp.jwt.verify.issuer";
    public static final String MP_JWT_VERIY_REQUIRE_ISS = "mp.jwt.verify.requireiss";
    
    // Other properties
    public static final String EXPIRY_GRACE_PERIOD = "expiry.grace.period";
    public static final String JWK_KEYS_URI = "jwk.keys.uri";
    public static final String JWK_KEYS_REFRESH_INTERVAL = "jwk.keys.refreshinterval";
    public static final String FOLLOW_MP_JWT11_RULES = "follow.mpjwt11.rules";
    
    private JWTAuthContextInfo authContextInfo;
    
    public DefaultJWTAuthContextInfo() {
        this.authContextInfo = new JWTAuthContextInfo();
    }
    
    public DefaultJWTAuthContextInfo(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
        loadSignerKey(authContextInfo);
    }
    
    public DefaultJWTAuthContextInfo(RSAPublicKey signerKey, String issuedBy) {
        authContextInfo = new JWTAuthContextInfo();
        authContextInfo.setProperty(RSAPublicKey.class.getName(), signerKey);
        authContextInfo.setProperty(MP_JWT_VERIY_PUBLIC_ISSUER, issuedBy);
    }
    private void loadSignerKey(JWTAuthContextInfo authContextInfo) {
        // Look to MP-JWT values first
        if (authContextInfo.getProperty(MP_JWT_VERIY_PUBLIC_KEY) != null) {
            RSAPublicKey signerKey = null;
            // Need to decode what this is...
            try {
                signerKey = (RSAPublicKey) KeyUtils.decodeJWKSPublicKey(
                    authContextInfo.getStringProperty(MP_JWT_VERIY_PUBLIC_KEY));
                //log.debugf("mpJwtPublicKey parsed as JWK(S)");
            } catch (Exception e) {
                // Try as PEM key value
                //log.debugf("mpJwtPublicKey failed as JWK(S), %s", e.getMessage());
                try {
                    signerKey = (RSAPublicKey) KeyUtils.decodePublicKey(
                        authContextInfo.getStringProperty(MP_JWT_VERIY_PUBLIC_KEY));
                    //log.debugf("mpJwtPublicKey parsed as PEM");
                } catch (Exception e1) {
                    throw new IllegalStateException(e1);
                }
            }
            if (signerKey != null) {
                authContextInfo.setProperty(RSAPublicKey.class.getName(), signerKey);
            }
        }
    }

    public RSAPublicKey getSignerKey() {
        return (RSAPublicKey)authContextInfo.getProperty(RSAPublicKey.class.getName());
    }

    public String getIssuedBy() {
        return authContextInfo.getStringProperty(MP_JWT_VERIY_PUBLIC_ISSUER);
    }

    public boolean isRequireIssuer() {
        Boolean value = authContextInfo.getBooleanProperty(MP_JWT_VERIY_REQUIRE_ISS);
        return value == null ? true : value;
    }

    
    public int getExpGracePeriodSecs() {
        Integer value = authContextInfo.getIntProperty(EXPIRY_GRACE_PERIOD);
        return value == null ? 60 : value;
    }
    
    public void setExpGracePeriodSecs(int expGracePeriod) {
        authContextInfo.setProperty(EXPIRY_GRACE_PERIOD, expGracePeriod);
    }

    public String getJwksUri() {
        return authContextInfo.getStringProperty(JWK_KEYS_URI);
    }

    public Integer getJwksRefreshInterval() {
        return authContextInfo.getIntProperty(JWK_KEYS_REFRESH_INTERVAL);
    }
    /**
     * Is the {@linkplain #jwksUri} a location that follows the MP-JWT 1.1 rules for the mp.jwt.verify.publickey.location
     * property? These rules allow for any URL type to one of PEM, JWK or JWKS contents.
     * @return true if jwksUri was set from the mp.jwt.verify.publickey.location, false otherwise
     */
    public boolean isFollowMpJwt11Rules() {
        Boolean value = authContextInfo.getBooleanProperty(FOLLOW_MP_JWT11_RULES);
        return value == null ? false : value;
    }
    
    public JWTAuthContextInfo getContextInfoProperties() {
        return authContextInfo;
    }
}

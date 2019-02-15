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
 *
 */
package io.smallrye.jwt.config;

import java.util.Optional;

import javax.enterprise.context.Dependent;
import javax.enterprise.inject.Produces;
import javax.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import io.smallrye.jwt.auth.principal.DefaultJWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

/**
 * A CDI provider for the JWTAuthContextInfo that obtains the necessary information from
 * MP config properties.
 */
@Dependent
public class JWTAuthContextInfoProvider {
    private static final String NONE = "NONE";
    private static final Logger log = Logger.getLogger(JWTAuthContextInfoProvider.class);

    // The MP-JWT spec defined configuration properties

    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.publickey", defaultValue = NONE)
    private Optional<String> mpJwtPublicKey;
    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.issuer", defaultValue = NONE)
    private String mpJwtIssuer;
    /**
     * @since 1.1
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.publickey.location", defaultValue = NONE)
    /**
     * @since 1.1
     */
    private Optional<String> mpJwtLocation;
    /**
     * Not part of the 1.1 release, but talked about.
     */
    @Inject
    @ConfigProperty(name = "mp.jwt.verify.requireiss", defaultValue = "true")
    private Optional<Boolean> mpJwtRequireIss;

    @Produces
    Optional<JWTAuthContextInfo> getOptionalContextInfo() {
        // Log the config values
        log.debugf("init, mpJwtPublicKey=%s, mpJwtIssuer=%s, mpJwtLocation=%s",
                   mpJwtPublicKey.orElse("missing"), mpJwtIssuer, mpJwtLocation.orElse("missing"));

        /*
        FIXME Due to a bug in MP-Config (https://github.com/wildfly-extras/wildfly-microprofile-config/issues/43) we need to set all
        values to "NONE" as Optional Strings are populated with a ConfigProperty.defaultValue if they are absent. Fix this when MP-Config
        is repaired.
         */
        if (NONE.equals(mpJwtPublicKey.get()) && NONE.equals(mpJwtLocation.get())) {
            return Optional.empty();
        }
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        // Look to MP-JWT values first
        if (mpJwtPublicKey.isPresent() && !NONE.equals(mpJwtPublicKey.get())) {
            contextInfo.setProperty(DefaultJWTAuthContextInfo.MP_JWT_VERIY_PUBLIC_KEY, mpJwtPublicKey.get());
        }

        if (mpJwtIssuer != null && !mpJwtIssuer.equals(NONE)) {
            contextInfo.setProperty(DefaultJWTAuthContextInfo.MP_JWT_VERIY_PUBLIC_ISSUER, mpJwtIssuer);
        } else {
            // If there is no expected issuer configured, don't validate it; new in MP-JWT 1.1
            contextInfo.setProperty(DefaultJWTAuthContextInfo.MP_JWT_VERIY_REQUIRE_ISS, false);
        }

        if (mpJwtRequireIss != null && mpJwtRequireIss.isPresent()) {
            contextInfo.setProperty(DefaultJWTAuthContextInfo.MP_JWT_VERIY_REQUIRE_ISS, mpJwtRequireIss.get());
        } else {
            // Default is to require iss claim
            contextInfo.setProperty(DefaultJWTAuthContextInfo.MP_JWT_VERIY_REQUIRE_ISS, true);
        }

        // The MP-JWT location can be a PEM, JWK or JWKS
        if (mpJwtLocation.isPresent() && !NONE.equals(mpJwtLocation.get())) {
            contextInfo.setProperty(DefaultJWTAuthContextInfo.JWK_KEYS_URI, mpJwtLocation.get());
            contextInfo.setProperty(DefaultJWTAuthContextInfo.FOLLOW_MP_JWT11_RULES, true);
        }

        return Optional.of(contextInfo);
    }

    public Optional<String> getMpJwtPublicKey() {
        return mpJwtPublicKey;
    }

    public String getMpJwtIssuer() {
        return mpJwtIssuer;
    }

    public Optional<String> getMpJwtLocation() {
        return mpJwtLocation;
    }

    public Optional<Boolean> getMpJwtRequireIss() {
        return mpJwtRequireIss;
    }

    @Produces
    public JWTAuthContextInfo getContextInfo() {
        return getOptionalContextInfo().get();
    }
}

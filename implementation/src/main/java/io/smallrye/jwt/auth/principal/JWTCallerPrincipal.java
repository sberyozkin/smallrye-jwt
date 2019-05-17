package io.smallrye.jwt.auth.principal;


import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonString;
import javax.json.JsonValue;
import javax.security.auth.Subject;

import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * An abstract CallerPrincipal implementation that provides access to the JWT claims that are required by
 * the microprofile token.
 */
public abstract class JWTCallerPrincipal implements JsonWebToken {
    private static final String TMP = "tmp";
    
    private String rawToken;
    private String tokenType;
    
    /**
     * Create a JWTCallerPrincipal with the caller's name
     *
     * @param rawToken - raw token value
     * @param tokenType - token type
     */
    public JWTCallerPrincipal(String rawToken, String tokenType) {
        this.rawToken = rawToken;
        this.tokenType = tokenType;
    }

    @Override
    public String getName() {
        String principalName = getClaim(Claims.upn.name());
        if (principalName == null) {
            principalName = getClaim(Claims.preferred_username.name());
            if (principalName == null) {
                principalName = getClaim(Claims.sub.name());
            }
        }
        return principalName;
    }
    
    @Override
    public Set<String> getClaimNames() {
        Set<String> names = new HashSet<>(doGetClaimNames());
        names.add(Claims.raw_token.name());
        return names;
    }
    
    protected abstract Collection<String> doGetClaimNames();

    @Override
    public <T> T getClaim(String claimName) {
        @SuppressWarnings("unchecked")
        T claimValue = Claims.raw_token.name().equals(claimName) ? (T)rawToken : (T)getClaimValue(claimName);
        return claimValue;
    }

    protected abstract Object getClaimValue(String claimName);

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
    
    public String toString() {
        return toString(false);
    }

    public Map<String, Object> getClaimsMap() {
        return doGetClaimsMap();
    }
    
    protected Map<String, Object> doGetClaimsMap() {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        for (String name : getClaimNames()) {
            map.put(name, getClaim(name));
        }
        return map;
    }
    
    public Map<String, List<Object>> getFlatClaims() {
        // Inspired by Jose4J, translated to the code below to support the factories
        // which do not use Jose4j (example, Keycloak factory or the factories which do not validate locally) 
        return doGetFlatClaims();
    }

    protected Map<String, List<Object>> doGetFlatClaims() {
        Map<String, Object> claimsMap = getClaimsMap();
        Map<String, List<Object>> flattenedClaims = new LinkedHashMap<>();
        for (Map.Entry<String,Object> e : claimsMap.entrySet()) {
            doGetFlatClaims(null, e.getKey(), e.getValue(), flattenedClaims);
        }
        return flattenedClaims;
    }

    @SuppressWarnings("rawtypes")
    protected void doGetFlatClaims(String baseName, String name, Object value, Map<String,List<Object>> flattenedClaims) {
        String key = (baseName == null ? "" : baseName + ".") + name;
        if (value instanceof Collection) {
            List<Object> list = new ArrayList<>();
            for (Object item : (Collection)value) {
                if (item instanceof Map) {
                    doGetFlatMapClaim(key, item, flattenedClaims);
                } else {
                    list.add(checkJsonString(item));
                }
            }
            flattenedClaims.put(key, list);
        } else if (value instanceof Map) {
            doGetFlatMapClaim(key, value, flattenedClaims);
        } else {
            flattenedClaims.put(key, Collections.singletonList(checkJsonString(value)));
        }
    }
    
    protected Object checkJsonString(Object item) {
        return item instanceof JsonString ? ((JsonString)item).getString() : item;
    }

    protected void doGetFlatMapClaim(String key, Object value, Map<String,List<Object>> flattenedClaims) {
        Map<?,?> mv = (Map<?,?>)value;
        for (Map.Entry<?,?> e : mv.entrySet()) {
            doGetFlatClaims(key, e.getKey().toString(), e.getValue(), flattenedClaims);
        }
    }

    /**
     * TODO: showAll is ignored and currently assumed true
     *
     * @param showAll - should all claims associated with the JWT be displayed or should only those defined in the
     *                JsonWebToken interface be displayed.
     * @return JWTCallerPrincipal string view
     */
    public String toString(boolean showAll) {
        String toString = "DefaultJWTCallerPrincipal{" +
                "id='" + getTokenID() + '\'' +
                ", name='" + getName() + '\'' +
                ", expiration=" + getExpirationTime() +
                ", notBefore=" + getClaim(Claims.nbf.name()) +
                ", issuedAt=" + getIssuedAtTime() +
                ", issuer='" + getIssuer() + '\'' +
                ", audience=" + getAudience() +
                ", subject='" + getSubject() + '\'' +
                ", type='" + tokenType + '\'' +
                ", issuedFor='" + getClaim("azp") + '\'' +
                ", authTime=" + getClaim("auth_time") +
                ", givenName='" + getClaim("given_name") + '\'' +
                ", familyName='" + getClaim("family_name") + '\'' +
                ", middleName='" + getClaim("middle_name") + '\'' +
                ", nickName='" + getClaim("nickname") + '\'' +
                ", preferredUsername='" + getClaim("preferred_username") + '\'' +
                ", email='" + getClaim("email") + '\'' +
                ", emailVerified=" + getClaim(Claims.email_verified.name()) +
                ", allowedOrigins=" + getClaim("allowedOrigins") +
                ", updatedAt=" + getClaim("updated_at") +
                ", acr='" + getClaim("acr") + '\'';
        StringBuilder tmp = new StringBuilder(toString);
        tmp.append(", groups=[");
        for (String group : getGroups()) {
            tmp.append(group);
            tmp.append(',');
        }
        tmp.setLength(tmp.length() - 1);
        tmp.append("]}");
        return tmp.toString();
    }
    
    protected JsonObject replaceMapClaims(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if (entryValue instanceof Map) {
                JsonObject entryJsonObject = replaceMapClaims((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if (entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapClaimValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if (entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if (entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if (entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if (entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    protected JsonValue wrapClaimValue(Object value) {
        JsonValue jsonValue = null;
        if (value instanceof JsonValue) {
            // This may already be a JsonValue
            jsonValue = (JsonValue) value;
        } else if (value instanceof String) {
            jsonValue = Json.createObjectBuilder()
                    .add(TMP, value.toString())
                    .build()
                    .getJsonString(TMP);
        } else if (value instanceof Number) {
            Number number = (Number) value;
            if ((number instanceof Long) || (number instanceof Integer)) {
                jsonValue = Json.createObjectBuilder()
                        .add(TMP, number.longValue())
                        .build()
                        .getJsonNumber(TMP);
            } else {
                jsonValue = Json.createObjectBuilder()
                        .add(TMP, number.doubleValue())
                        .build()
                        .getJsonNumber(TMP);
            }
        } else if (value instanceof Boolean) {
            Boolean flag = (Boolean) value;
            jsonValue = flag ? JsonValue.TRUE : JsonValue.FALSE;
        } else if (value instanceof Collection) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            Collection list = (Collection) value;
            for (Object element : list) {
                if (element instanceof String) {
                    arrayBuilder.add(element.toString());
                } else {
                    JsonValue jvalue = wrapClaimValue(element);
                    arrayBuilder.add(jvalue);
                }
            }
            jsonValue = arrayBuilder.build();
        } else if (value instanceof Map) {
            jsonValue = replaceMapClaims((Map) value);
        }
        return jsonValue;
    }
    
    /**
     * Determine the custom claims in the set
     *
     * @param claimNames - the current set of claim names in this token
     * @return the possibly empty set of names for non-Claims claims
     */
    protected Set<String> filterCustomClaimNames(Collection<String> claimNames) {
        Set<String> customNames = new HashSet<>(claimNames);
        for (Claims claim : Claims.values()) {
            customNames.remove(claim.name());
        }
        return customNames;
    }
    
    protected Claims getClaimType(String claimName) {
    	Claims claimType = Claims.UNKNOWN;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {
        }
        return claimType;
	}
}

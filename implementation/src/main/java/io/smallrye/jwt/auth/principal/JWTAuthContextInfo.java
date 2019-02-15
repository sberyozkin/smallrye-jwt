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


import java.util.HashMap;
import java.util.Map;

/**
 * The map of configuration keys and values.
 */
public class JWTAuthContextInfo {
    private Map<String, Object> properties = new HashMap<>();
    
    public void setProperty(String key, Object value) {
        properties.put(key, value);
    }
    
    public Object getProperty(String key) {
        return properties.get(key);
    }
    
    public <T> T getProperty(String key, Class<T> cls) {
        return properties.containsKey(key) ? cls.cast(properties.get(key)) : null;
    }
    
    public String getStringProperty(String key) {
        return getProperty(key, String.class);
    }
    
    public Integer getIntProperty(String key) {
        Object value = getProperty(key);
        return value instanceof Integer ? Integer.class.cast(value) : value instanceof String
            ? Integer.valueOf((String)value) : null;
    }
    
    public Boolean getBooleanProperty(String key) {
        Object value = getProperty(key);
        return value instanceof Boolean ? Boolean.class.cast(value) : value instanceof String
            ? Boolean.valueOf((String)value) : null; 
    }
    
}

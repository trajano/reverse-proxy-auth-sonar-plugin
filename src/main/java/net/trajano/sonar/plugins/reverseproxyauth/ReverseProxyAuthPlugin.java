package net.trajano.sonar.plugins.reverseproxyauth;

import java.util.Arrays;
import java.util.List;

import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.SonarPlugin;

/**
 * Plugin entry point.
 */
@Properties(@Property(key = "reverseproxyauth.header.name", name = "Header Name", defaultValue = "X-Forwarded-User"))
public class ReverseProxyAuthPlugin extends SonarPlugin {
    @SuppressWarnings("rawtypes")
    @Override
    public List<Class> getExtensions() {
        return Arrays.<Class> asList(ReverseProxyAuthRealm.class,
                ReverseProxyAuthServletFilter.class);
    }
}

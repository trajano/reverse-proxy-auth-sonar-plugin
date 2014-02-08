package net.trajano.sonar.plugins.reverseproxyauth;

import java.util.Collections;
import java.util.List;

import net.trajano.sonar.plugins.reverseproxyauth.internal.Extensions;

import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.SonarPlugin;

/**
 * Plugin entry point.
 */
@Properties({
        @Property(key = "reverseproxyauth.header.name", name = "Header Name", defaultValue = "X-Forwarded-User"),
        @Property(key = "reverseproxyauth.localhost", name = "Hostname to allow Sonar executions", defaultValue = "localhost") })
public class ReverseProxyAuthPlugin extends SonarPlugin {
    @SuppressWarnings("rawtypes")
    @Override
    public List<Class> getExtensions() {
        return Collections.<Class> singletonList(Extensions.class);
    }
}

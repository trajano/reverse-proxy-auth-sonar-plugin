package net.trajano.sonar.plugins.reverseproxyauth;

import org.sonar.api.Plugin;
import org.sonar.api.Properties;
import org.sonar.api.Property;
import org.sonar.api.PropertyType;

/**
 * Plugin entry point.
 */
@Properties({
    @Property(key = ReverseProxyAuthSettings.HEADER_NAME,
        name = "Header Name",
        defaultValue = "X-Forwarded-User"),
    @Property(key = ReverseProxyAuthSettings.LOCALHOST,
        name = "Hostname to allow Sonar executions",
        defaultValue = "localhost"),
    @Property(key = ReverseProxyAuthSettings.ALLOW_NEW_USERS,
        name = "Allow new users to be be created",
        defaultValue = "true",
        type = PropertyType.BOOLEAN)
})
public class ReverseProxyAuthPlugin implements
    Plugin {

    /**
     * Plugin key.
     */
    public static final String KEY = "reverseproxyauth";

    @Override
    public void define(final Context context) {

        context.addExtension(ReverseProxyAuthSettings.class);
        context.addExtension(ReverseProxyAuthRealm.class);
        context.addExtension(ReverseProxyAuthUsersIdentityProvider.class);
        context.addExtension(ValidateRedirectionFilter.class);
    }

}

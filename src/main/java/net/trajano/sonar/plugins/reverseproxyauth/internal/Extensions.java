package net.trajano.sonar.plugins.reverseproxyauth.internal;

import java.util.List;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthRealm;
import net.trajano.sonar.plugins.reverseproxyauth.ValidateRedirectionFilter;

import org.sonar.api.ExtensionProvider;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

import com.google.common.collect.Lists;

/**
 * Extensions used by the plugin. This is dynamically determined.
 * 
 * @author Archimedes Trajano
 */
public final class Extensions extends ExtensionProvider implements
        ServerExtension {
    /**
     * Settings that are injected.
     */
    private final Settings settings;

    /**
     * Constructs the {@link ExtensionProvider}.
     * 
     * @param settings
     *            injected settings
     */
    public Extensions(final Settings settings) {
        super();
        this.settings = settings;
    }

    /**
     * Provides the relevant extensions if the security realm is defined.
     */
    @SuppressWarnings("rawtypes")
    @Override
    public Object provide() {
        final List<Class> extensions = Lists.newArrayList();
        if (ReverseProxyAuthPlugin.KEY.equalsIgnoreCase(settings
                .getString("sonar.security.realm"))) {
            extensions.add(ReverseProxyAuthRealm.class);
            extensions.add(ValidateRedirectionFilter.class);
        }
        return extensions;
    }
}

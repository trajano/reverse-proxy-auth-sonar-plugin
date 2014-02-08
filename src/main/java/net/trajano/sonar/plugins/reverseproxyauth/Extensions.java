package net.trajano.sonar.plugins.reverseproxyauth;

import java.util.List;

import org.sonar.api.Extension;
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
     * Returns an empty list if there realm is not set to prevent class not
     * found errors on the sonar runners.
     * 
     * @return list of extensions that the plugin provides.
     */
    @Override
    public List<Class<? extends Extension>> provide() {
        final List<Class<? extends Extension>> extensions = Lists
                .newArrayList();
        if (ReverseProxyAuthPlugin.KEY.equalsIgnoreCase(settings
                .getString("sonar.security.realm"))) {
            extensions.add(ReverseProxyAuthRealm.class);
            extensions.add(ValidateRedirectionFilter.class);
        }
        return extensions;
    }
}

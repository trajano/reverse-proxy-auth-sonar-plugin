package net.trajano.sonar.plugins.reverseproxyauth.internal;

import java.util.List;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthRealm;
import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthServletFilter;

import org.sonar.api.ExtensionProvider;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

import com.google.common.collect.Lists;

public final class Extensions extends ExtensionProvider implements
        ServerExtension {
    private final Settings settings;

    public Extensions(final Settings settings) {
        this.settings = settings;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public Object provide() {
        final List<Class> extensions = Lists.newArrayList();
        if ("reverseproxyauth".equalsIgnoreCase(settings
                .getString("sonar.security.realm"))) {
            extensions.add(ReverseProxyAuthRealm.class);
            extensions.add(ReverseProxyAuthServletFilter.class);
        }
        return extensions;
    }
}
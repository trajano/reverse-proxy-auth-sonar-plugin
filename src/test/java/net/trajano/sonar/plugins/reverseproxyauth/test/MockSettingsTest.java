package net.trajano.sonar.plugins.reverseproxyauth.test;

import static org.mockito.Mockito.mock;
import net.trajano.sonar.plugins.reverseproxyauth.internal.ReverseProxyAuthenticator;

import org.junit.Test;
import org.sonar.api.config.Settings;

/**
 * Tests the module.
 */
public class MockSettingsTest {

    /**
     * Tests the module method.
     */
    @Test
    public void testMethod() {
        final Settings settings = mock(Settings.class);
        new ReverseProxyAuthenticator(settings);
    }
}
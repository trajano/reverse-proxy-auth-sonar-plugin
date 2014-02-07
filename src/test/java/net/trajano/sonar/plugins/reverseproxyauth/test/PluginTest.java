package net.trajano.sonar.plugins.reverseproxyauth.test;

import net.trajano.sonar.plugins.reverseproxyauth.ReverseProxyAuthPlugin;

import org.junit.Test;

public class PluginTest {
    @Test
    public void testListExtensions() {
        new ReverseProxyAuthPlugin().getExtensions();
    }
}

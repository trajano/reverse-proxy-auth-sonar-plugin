Implementation details
======================

Assuming Sonarqube is configured to force authentication, the following sequence occurs:

1. SonarQube detects that the user is not logged on
2. SonarQube will redirect to  `/sessions/new` 
3. `/sessions/new` which is filtered using `ValidationRedirectionFilter`
4. The filter automatically redirects to `/sessions/init/reverseproxyauth` 
5. `/sessions/init/reverseproxyauth` that will invoke the `ReverseProxyAuthUsersIdentityProvider` 
6. `ReverseProxyAuthUsersIdentityProvider` will then set the credentials then redirect to `reverseproxyauth/redirect_back_or_home_url`
7. `reverseproxyauth/redirect_back_or_home_url` will invoke `redirect_back_or_home_url` in the Rails context which will peform the redirect back to the original request or the home if not available.

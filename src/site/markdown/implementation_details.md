Implementation details
======================

Sonar is configured to force authentication, when it detects that the user is
lot logged on it will redirect to  `/sessions/new` which is filtered to
automatically redirect to `/reverseproxyauth/validate` that will set the
current user details.

If the connection is requesting "localhost" (configurable) it will accept any
credentials.

# Miniban

Ban hosts on webservers and reverse proxies.

### .htaccess method for Apache

Based on which HTTP header hosts should be banned:

- Apache without reverse proxy
- CloudFlare
- Rackspace
- Varnish
- HA proxy

```apache
# Apache < 2.3
<IfModule !mod_authz_core.c>
    Order allow,deny
    Deny from env=mini_ban
    Allow from all
    Satisfy All
</IfModule>

# Apache ≥ 2.3
<IfModule mod_authz_core.c>
    <RequireAll>
        Require all granted
        Require not env mini_ban
    </RequireAll>
</IfModule>

# Mini Ban for Apache directory configuration
SetEnvIf Remote_Addr "^192\.168\.1\.100$" mini_ban

# CloudFlare header
#SetEnvIf X-FORWARDED-FOR "^192\.168\.1\.100$" mini_ban

# Incapsula

# Rackspace header
#SetEnvIf X-CLUSTER-CLIENT-IP "^192\.168\.1\.100$" mini_ban

# Varnish

# HA proxy

```

### RewriteMap method for Apache

```apache
# Virtual host configuration
RewriteEngine On
RewriteMap ipblocklist "txt:/path/to/ipblocklist.txt"
RewriteCond "${ipblocklist:%{REMOTE_ADDR}|NOT-FOUND}" !=NOT-FOUND
RewriteRule ^ - [F]
```

### Nginx user configuration

```nginx

```

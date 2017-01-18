// Varnish VCL for:
// - Varnish 4.1 or higher with xkey vmod (via varnish-modules package, or via Varnish Plus)
// - eZ Platform 1.7 or higher (configured for Varnish, incl with Symfony HttpCache Proxy disabled)
//
// Complete VCL example, further reading on:
// - https://symfony.com/doc/current/http_cache/varnish.html
// - https://foshttpcache.readthedocs.io/en/stable/varnish-configuration.html
// - https://github.com/varnish/varnish-modules/blob/master/docs/vmod_xkey.rst
// - https://www.varnish-cache.org/docs/trunk/users-guide/vcl.html

vcl 4.0;
import std;
import xkey;

// Our Backend - Assuming that web server is listening on port 80
// Replace the host to fit your setup
backend ezplatform {
    .host = "web";
    .port = "80";
}

// ACL for invalidators IP
acl invalidators {
    "127.0.0.1";
    "172.16.0.0"/20;
    "app";
}

// ACL for debuggers IP
acl debuggers {
    "127.0.0.1";
    "172.16.0.0"/20;
}

// Called at the beginning of a request, after the complete request has been received
sub vcl_recv {

    // Set the backend
    set req.backend_hint = ezplatform;

    // Advertise Symfony for ESI support
    set req.http.Surrogate-Capability = "abc=ESI/1.0";

    // Varnish, in its default configuration, sends the X-Forwarded-For header but does not filter out Forwarded header
    unset req.http.Forwarded;

    // Remove all cookies except the session ID.
    if (req.http.Cookie) {
        set req.http.Cookie = ";" + req.http.Cookie;
        set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
        set req.http.Cookie = regsuball(req.http.Cookie, ";(eZSESSID[^=]*)=", "; \1=");
        set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
        set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

        if (req.http.Cookie == "") {
            // If there are no more cookies, remove the header to get page cached.
            unset req.http.Cookie;
        }
    }

    // Trigger cache purge if needed
    call ez_purge;

    // Don't cache requests other than GET and HEAD.
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    // Don't cache Authenticate & Authorization
    // You may remove this when using REST API with basic auth.
    if (req.http.Authenticate || req.http.Authorization) {
        if (client.ip ~ debuggers) {
            set req.http.X-Debug = "Not Cached according to configuration (Authorization)";
        }
        return (hash);
    }

    // Do a standard lookup on assets (don't vary by user context hash)
    // Note that file extension list below is not extensive, so consider completing it to fit your needs.
    if (req.url ~ "\.(css|js|gif|jpe?g|bmp|png|tiff?|ico|img|tga|wmf|svg|swf|ico|mp3|mp4|m4a|ogg|mov|avi|wmv|zip|gz|pdf|ttf|eot|wof)$") {
        return (hash);
    }

    // Retrieve client user hash and add it to the forwarded request.
    call ez_user_context_hash;

    // If it passes all these tests, do a lookup anyway.
    return (hash);
}

// Called when a cache lookup is successful. The object being hit may be stale: It can have a zero or negative ttl with only grace or keep time left.
sub vcl_hit {
   if (obj.ttl >= 0s) {
       // A pure unadultered hit, deliver it
       return (deliver);
   }
   if (obj.ttl + obj.grace > 0s) {
       // Object is in grace, logic below in this block is what differs from default:
       // https://varnish-cache.org/docs/5.0/users-guide/vcl-grace.html#grace-mode
       if (!std.healthy(req.backend_hint)) {
           // Service is unhealthy, deliver from cache
           return (deliver);
       } else if (req.url ~ "^/api/ezp/v2" && req.http.referer ~ "/ez$") {
           // Request is for Platform UI for REST API, fetch it
           return (miss);
       }
       // By default deliver cache, automatically triggers a background fetch
       return (deliver);
   }
   // fetch & deliver once we get the result
   return (miss);
}

// Called when the requested object has been retrieved from the backend
sub vcl_backend_response {

    if (bereq.http.accept ~ "application/vnd.fos.user-context-hash"
        && beresp.status >= 500
    ) {
        return (abandon);
    }

    // Check for ESI acknowledgement and remove Surrogate-Control header
    if (beresp.http.Surrogate-Control ~ "ESI/1.0") {
        unset beresp.http.Surrogate-Control;
        set beresp.do_esi = true;
    }

    // Make Varnish keep all objects for up to 1 hour beyond their TTL, see vcl_hit for Request logic
    set beresp.grace = 1h;
}

// Handle purge
// You may add FOSHttpCacheBundle tagging rules
// See http://foshttpcache.readthedocs.org/en/latest/varnish-configuration.html#id4
sub ez_purge {

     if (req.method == "PURGE") {
        if (!client.ip ~ invalidators) {
             return (synth(403, "Forbidden"));
         }
         set req.http.n-gone = xkey.softpurge(req.http.xkey);

         return (synth(200, "Invalidated "+req.http.n-gone+" objects"));
     }

     // @todo, like on FOS PR also support purge by url and maybe also ban for BC
}

// Sub-routine to get client user hash, for context-aware HTTP cache.
sub ez_user_context_hash {

    // Prevent tampering attacks on the hash mechanism
    if (req.restarts == 0
        && (req.http.accept ~ "application/vnd.fos.user-context-hash"
            || req.http.X-User-Hash
        )
    ) {
        return (synth(400));
    }

    if (req.restarts == 0 && (req.method == "GET" || req.method == "HEAD")) {
        // Backup accept header, if set
        if (req.http.accept) {
            set req.http.X-Fos-Original-Accept = req.http.accept;
        }
        set req.http.accept = "application/vnd.fos.user-context-hash";

        // Backup original URL
        set req.http.X-Fos-Original-Url = req.url;
        set req.url = "/_fos_user_context_hash";

        // Force the lookup, the backend must tell not to cache or vary on all
        // headers that are used to build the hash.
        return (hash);
    }

    // Rebuild the original request which now has the hash.
    if (req.restarts > 0
        && req.http.accept == "application/vnd.fos.user-context-hash"
    ) {
        set req.url = req.http.X-Fos-Original-Url;
        unset req.http.X-Fos-Original-Url;
        if (req.http.X-Fos-Original-Accept) {
            set req.http.accept = req.http.X-Fos-Original-Accept;
            unset req.http.X-Fos-Original-Accept;
        } else {
            // If accept header was not set in original request, remove the header here.
            unset req.http.accept;
        }

        // Force the lookup, the backend must tell not to cache or vary on the
        // user hash to properly separate cached data.

        return (hash);
    }
}

sub vcl_deliver {
    // On receiving the hash response, copy the hash header to the original
    // request and restart.
    if (req.restarts == 0
        && resp.http.content-type ~ "application/vnd.fos.user-context-hash"
    ) {
        set req.http.X-User-Hash = resp.http.X-User-Hash;

        return (restart);
    }

    // If we get here, this is a real response that gets sent to the client.

    // Remove the vary on context user hash, this is nothing public. Keep all
    // other vary headers.
    set resp.http.Vary = regsub(resp.http.Vary, "(?i),? *X-User-Hash *", "");
    set resp.http.Vary = regsub(resp.http.Vary, "^, *", "");
    if (resp.http.Vary == "") {
        unset resp.http.Vary;
    }

    // Sanity check to prevent ever exposing the hash to a client.
    unset resp.http.X-User-Hash;

    if (client.ip ~ debuggers) {
        if (resp.http.X-Varnish ~ " ") {
            set resp.http.X-Cache = "HIT";
        } else {
            set resp.http.X-Cache = "MISS";
        }
    } else {
        // Remove tag headers when delivering to non debug client
        unset resp.http.xkey;
    }
}

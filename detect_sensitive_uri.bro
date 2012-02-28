##! sensitive URL attack detection in HTTP.

@load base/frameworks/notice
@load base/protocols/http

module HTTP;

export {
        redef enum Notice::Type += {
                HTTP_SensitiveURI,
        };

        ## Regular expression is used to match URI based Sensitive Urls.
        const sensitive_URIs =
                   /etc\/(passwd|shadow|netconfig)/
                | /IFS[ \t]*=/
                | /nph-test-cgi\?/
                | /(%0a|\.\.)\/(bin|etc|usr|tmp)/
                | /[Ee][Nn][Ii][Rr][Oo][Nn]00/
                | /[Ss][Qq][Ll][Pp][Aa][Tt][Cc][Hh]\.[Pp][Hh][Pp]/
                | /\/Admin_files\/order\.log/
                | /\.\.\/\.\.\/\.\.\/\.\.\/\.\.\//
                | /\/[Aa][Dd][Mm][Ii][Nn][Ii][Ss][Tt][Rr][Aa][Tt][Oo][Rr]/
                | /\/[Mm][Yy][Ss][Qq][Ll]/
                | /\/[Pp][Hh][Pp][Mm][Yy][Aa][Dd][Mm][Ii][Nn]/
                | /\/[Ll][Oo][Gg][Ii][Nn]\.[Pp][Hh][Pp]/
                | /\/adodb-perf-module.inc\.php/
                | /\/[Aa][Dd][Mm][Ii][Nn]\.[Pp][Hh][Pp]/
                | /\/[Ss][Ee][Tt][Uu][Pp]\-[Cc][Oo][Nn][Ff][Ii][Gg]\.[Pp][Hh][Pp]/
&redef;
		## IPs that are allowed to access the sensitive pages
		const ignored_ips =
                {[1.2.3.4],
                [10.0.0.1]}
&redef;
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
        {
        local orig = c$id$orig_h;
        local log_it = F;
        local URI = unescaped_URI;

        if  ( orig in ignored_ips )
                return;

        if ( sensitive_URIs in unescaped_URI )
                {
                        log_it = T;
                }
                if ( log_it )
                        NOTICE([$note=HTTP_SensitiveURI,
                                $method = method, $URL = URI,
                                $msg=fmt("%s %s: %s %s",
                                        id_string(c$id), c$addl, method, URI)]);
        }

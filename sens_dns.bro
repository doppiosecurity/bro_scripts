##! sensitive DNS lookup.

@load base/frameworks/notice
@load base/protocols/dns

module DNS;

export {
        redef enum Notice::Type += {
                SensitiveDNS_Lookup,
        };
        const hot_dns =
                /^lemonde.pezcyclingnews.com/ |
                /^lemonde.velonews.com/ |
                /^www.beammeupscotty.com/ |
                /^first.second.third.yahoo.com/
&redef;
}
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=5
        {
        local orig = c$id$orig_h;
        local resp = c$id$resp_h;
        if ( hot_dns in query )

                NOTICE([$note=SensitiveDNS_Lookup,
                        $msg=fmt("name lookup of %s", query),
                        $conn=c,
                        $sub="name lookup"]);
        }

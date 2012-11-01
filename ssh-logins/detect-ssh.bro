# Detect SSH connections with a built in whitelist


@load base/frameworks/notice

module SSH;

export {
        redef enum Notice::Type += {
                SSH_Connection_Success,
                SSH_Connection_Fail,
        };
# identify hosts who will begin a ssh session
        const ignored_ssh_hosts_init =
                                {
                                [10.0.0.1],           # Blah
                                [10.0.0.2],           # Blah 1
                                } &redef;
# identify hosts who will recieve a ssh session
        const ignored_ssh_hosts_receive =
                                {
                                [1.2.3.4],            # blah 3
                                [1.2.3.5],            # blah 2
                                } &redef;


}

event SSH::heuristic_successful_login(c: connection)
{
        local id = c$id;
        #if ( ignored_ssh_hosts !in resp_h )
        if (id$orig_h !in ignored_ssh_hosts_init &&
                id$resp_h !in ignored_ssh_hosts_receive )
                {
                        NOTICE([$note=SSH_Connection_Success,
                        $conn=c,
                        $msg=fmt("Successful SSH login by  %s", id$orig_h)]);
                }

}
event SSH::heuristic_failed_login(c: connection)
        {
        local id = c$id;
        if (id$orig_h !in ignored_ssh_hosts_init &&
                id$resp_h !in ignored_ssh_hosts_receive )
                {
                        NOTICE([$note=SSH_Connection_Fail,
                        $conn=c,
                        $msg=fmt("Successful SSH login by  %s", id$orig_h)]);
                }

}

##! Detect RSA secureID Login failures in Syslog with a Cisco ASA

@load base/frameworks/notice
@load base/protocols/syslog

module Syslog;

export {
        redef enum Notice::Type += {
                SYSLOG::RSA_Login_FAILURE
        };

        ## two const to identify your RSA server name and the fail message
        const RSA_Info = /rsa.company.com : user/ &redef;
        const RSA_Fail = /authentication Rejected/ &redef;
}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=5
        {
        if ( RSA_Info in msg && RSA_Fail in msg)
          {
          NOTICE([$note=SYSLOG::RSA_Login_FAILURE,
          $msg=("RSA Login Failure"),
          $sub=fmt(msg, c$syslog),
          $conn=c,
          $suppress_for=1min]);
          }
        }
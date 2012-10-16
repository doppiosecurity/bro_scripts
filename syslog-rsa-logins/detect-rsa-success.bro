##! Detect RSA secureID Login successes in Syslog with a Cisco ASA

@load base/frameworks/notice
@load base/protocols/syslog

module Syslog;

export {
        redef enum Notice::Type += {
                SYSLOG::RSA_Login_SUCCESS
        };

        ## two const to identify your RSA server name and the success message
        const RSA_Info = /rsa.company.com : user/ &redef;
        const RSA_Success = /authentication Successful/ &redef;
}

event syslog_message(c: connection, facility: count, severity: count, msg: string) &priority=5
        {
        if ( RSA_Info in msg && RSA_Success in msg)
          {
          NOTICE([$note=SYSLOG::RSA_Login_SUCCESS,
          $msg=("RSA Login Success Detected"),
          $sub=fmt(msg, c$syslog),
          $conn=c,
          $suppress_for=1min]);
          }
        }

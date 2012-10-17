# detect long and slow connections


@load base/frameworks/notice

module Conn;

export {
        redef enum Notice::Type += {
                LongConnectionHTTP,
        };
        const  thresh_size = 20*1024*1024;
        const  thresh_speed = 131072;

}

event connection_state_remove(c: connection) &priority=-5
        {
                local service = determine_service(c);
                local a = c$resp$size;
                local b = interval_to_double(c$duration);
                local p = a/b;

                local k = c$orig$size;
                local v = k/b;
                if ( (service == "http" || service == "https") && ((c$orig$size > thresh_size && v < thresh_speed) || (c$resp$size > thresh_size && p < thresh_speed )))
                        {

                        NOTICE([$note=LongConnectionHTTP,
                                $msg=fmt("Connection from [%s], [%s] Seconds, Bytes received: [%s], Bytes Transfered: [%s]", HTTP::build_url_http(c$http), c$duration, c$orig$size, c$resp$size),
                                $conn=c,
                                $sub="Long Connection"]);
                        }

        }

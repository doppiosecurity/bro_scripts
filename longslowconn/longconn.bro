# detect long connections


@load base/frameworks/notice

module Conn;

export {
        redef enum Notice::Type += {
                LongConnectionHTTP,
        };
        const  thresh_size = 20*1024*1024;
        const  thresh_speed = 131072;

        const longconn_ignore_url = /5min.com|adobe.com|aigamedev.com|akamaihd.net|allocine.fr|aol.com|arenanetworks.com|blip.tv|cvcdn.com|dailymotion.com|deathfall.com|dell.com|digium.com|dmcdn.net|eurogamer.net|gamekult.com|gamespotcdn.com|gbtv.com|google.com|googlevideo.com|grooveshark.com|jeuxvideo.com|kanaldude.tv|lego.com|lemouv.fr|libsyn.com|llnwd.net|m6web.fr|macromedia.com|microsoft.com|minoto-video.com|mozilla.net|mozilla.org|msvp.net|no-ip.org:5000|nolifefiler.com|novafile.com|nvidia.com|oracle.com|pangolia.com|perforce.com|radionomy.com|rockband.com|rockradio.com|sankakustatic.com|seagate.com|steampowered.com|streamlike.com|streamtheworld.com|terrescommunes.fr|tumblr.com|turner.com|tuxboard.com|tv-radio.com|userapi.com|ustream.tv|vimeo.com|windowsupdate.com|youtube.com/ &redef;

}



event connection_state_remove(c: connection) &priority=-5
        {
                local service = determine_service(c);
                local a = c$resp$size;
                local b = interval_to_double(c$duration);
                local p = a/b;

                local k = c$orig$size;
                local v = k/b;
                if ( (service == "http" || service == "https") && ((c$orig$size > thresh_size && v < thresh_speed) || (c$resp$size > thresh_size && p < thresh_speed )) &&( longconn_ignore_url !in c$http$host)  )
                        {

                        NOTICE([$note=LongConnectionHTTP,
                                $msg=fmt("Connection from [%s], [%s] Seconds, Bytes received: [%s], Bytes Transfered: [%s]", HTTP::build_url_http(c$http), c$duration, c$orig$size, c$resp$size),
                                $conn=c,
                                $sub="Long Connection"]);
                        }

        }



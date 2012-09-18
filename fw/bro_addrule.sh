#!/bin/bash

################################################################################################
## Requires https://github.com/doppiosecurity/bro_scripts/blob/master/detect_sensitive_uri.bro
##
## The above script marks the offending traffic
##
## Also requires block.ips
##
## And neverblock.ips
##
## both need to have content and sorted at all times and only have IPs :)
##
################################################################################################

_4444=#########yourpassword############
xyz="show banner"
prompt="*#"
promptconf="*(config)#"
promptconfnet="*(config-network)#"
bro_current_logs='/usr/local/bro/logs/current/'

Today="`date +%m%d%y-%H%M`"
Path='/usr/local/bro/fw'
# Query alarm log for new IPs
# cat /bro/logs/current/alarm.log | awk '{print $5}' | sort -u | sed 's/sa=//g' | sed '/^$/d' > $Path/block.ips.$Today
grep "SensitiveURI" /usr/local/bro/logs/current/notice.log | awk '{print $9}' | /bin/egrep -o ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ | sort -u > $Path/block.ips.$Today
# Make sure they dont already exist in our block list

cat $Path/block.ips | sort -u > $Path/block.ip
mv  $Path/block.ip $Path/block.ips

comm -23 $Path/block.ips.$Today $Path/block.ips > $Path/new.ips
# Make sure they are not one of our never block IPs
comm -23 $Path/new.ips $Path/neverblock.ips >$Path/final.ips
# Remove new.ips
rm $Path/block.ips.$Today
rm $Path/new.ips

# Set Final IPs as a Var
Files=$Path/final.ips
# If there are IPs in the file then execute for loop to add them to the block list
if [[ -s $Files ]] ; then
        for i in `cat $Files`
        do
        echo $i >> $Path/block.ips

expect -c "
spawn ssh -l username 10.0.0.1
sleep 1
expect {
        "*word:"
       {
send "$_4444"\r
       }
       }
sleep 1
expect {
       "*"
       {
send "en"\r
       }
       }
sleep 1
expect {
       "*word:"
       {
send \"$_4444\"
send \r
       }
       }
sleep 1
expect {
       "$prompt"
       {
send \"conf t\"
send \r
       }
       }
sleep 1
expect {
       "$promptconf"
       {
send \"object-group network blocked\"
send \r
      }
      }
sleep 1
expect {
       "$promptconfnet"
        {
log_file /usr/local/bro/fw/bro_ruleadd/ruleadd_$i_$Today.txt
send  \"network-object $i 255.255.255.255\"
send \r
       }
       }
sleep 1
expect {
      "$promptconfnet"
       {
send \r
       }
       }
sleep 1
expect {
       "$promptconfnet"
       {
send \"logout\"
send \r
       }
       }
expect  eof "


######## For Bro versions 2.0 or higher ############################
head -10 $bro_current_logs/http.log > /usr/local/bro/fw/bro_ruleadd/$i-temp-$Today.txt
grep $i $bro_current_logs/http.log >> /usr/local/bro/fw/bro_ruleadd/$i-temp-$Today.txt
cat /usr/local/bro/fw/bro_ruleadd/$i-temp-$Today.txt | /usr/local/bro/bin/bro-cut -d ts id.orig_h method host uri post_body | grep $i | /usr/bin/tac | /usr/bin/head -n 10000 >> /usr/local/bro/fw/bro_ruleadd/ruleadd_$i_$Today.txt

url=`grep $i $bro_current_logs/notice.log | awk '{print $14}' | tail -1`

cat - /usr/local/bro/fw/bro_ruleadd/ruleadd_$i_$Today.txt << EOF | /usr/sbin/sendmail -t
to:you@youremail.com
from:Bro-Rule-Add@brosensor.com
subject: $i $url

EOF
rm /usr/local/bro/fw/bro_ruleadd/$i-temp-$Today.txt
        done
# Clean up files created
        rm $Files
	sort $Path/block.ips > $Path/block.ips.sorted
        rm $Path/block.ips
        mv $Path/block.ips.sorted $Path/block.ips


else
#echo " empty "
#Cleanup
rm $Files
fi ;


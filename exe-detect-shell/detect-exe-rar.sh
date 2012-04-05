#!/bin/bash
scriptpath=/usr/local/bro/logs
outpath=/usr/local/bro/scripts/http

# search http.log for the following file types and make sure they are not in the ignore url list
# if you wish to white list a domain, add it to the ignore_url list
grep -E "application/x-rar-compressed|application/x-executable|application/x-dosexec" $scriptpath/current/http.log | grep -vE -f $outpath/ignore_url > $outpath/exe_urls
# gawk the time and change it to human readable
grep -vE -f $outpath/detected $outpath/exe_urls | gawk '{$1=strftime("%c",$1)} {print $1 " - " $9 " - " $10}' > $outpath/final
# set out as var.
out=$outpath/final
# go through list and send you an email 
if [[ -s $out ]] ; then
cat - $outpath/final << EOF | /usr/sbin/sendmail -t
TO:you@yourplace.com
FROM:Bro@bro.com
SUBJECT: Executeable and RAR downloaded

EOF
# add to detected, this is so you won't alert on ones that you have already been emailed about
# I log the epoch timestamp in the detected file.
cat $outpath/exe_urls | awk '{print $1}' >> $outpath/detected
# sort the detected, so that when you compare there will be no errors
sort -u $outpath/detected > $outpath/temp123
mv $outpath/temp123 $outpath/detected
#clean up
rm $outpath/final

else
#clean up
rm $outpath/final
fi ;

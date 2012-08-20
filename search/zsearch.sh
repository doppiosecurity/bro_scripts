#!/bin/bash

#Will H. bash fu

#Dates:
tdate=`date '+%Y%m%d'`

#Dirs
WORKDIR='/usr/local/bro/search'
TEMPDIR='/usr/local/bro/search/tmp'
CURRENTLOG='/usr/local/bro/logs/current'

echo -n "What date would you like to search? (format- 2012-08-03): "
read -e OLDER

echo -n "Which log file? (http, conn, ssl, ssh, dns): "
read -e LOGFILE

echo -n "What term would you like to search? (IP, website, whateva): "
read -e SEARCHTERM

OLDLOG='/usr/local/bro/logs'

touch $WORKDIR/$OLDER-$SEARCHTERM.out

head -7 $CURRENTLOG/$LOGFILE.log > $WORKDIR/$OLDER-$SEARCHTERM.out

zgrep $SEARCHTERM $OLDLOG/$OLDER/$LOGFILE.* >> $WORKDIR/$OLDER-$SEARCHTERM.out

echo "*"
echo "*"
echo "*"
echo "*"
echo "Your file is done, use bro-cut now without reading an entire logfile"
echo "*"
echo "*"
echo "now you can run: cat filename | bro-cut -d ts uri user_agent"
echo "*"
echo "or what ever, see if i care...."
echo "*"



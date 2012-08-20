#!/bin/bash

#Will H. bash fu

#Dates:
tdate=`date '+%Y%m%d'`

#Dirs
WORKDIR='/usr/local/bro/search'
TEMPDIR='/usr/local/bro/search/tmp'
CURRENTLOG='/usr/local/bro/logs/current'

echo -n "Which log file? (http, conn, ssl, ssh, dns): "
read -e LOGFILE

echo -n "What term would you like to search? (IP, website, whateva): "
read -e SEARCHTERM

touch $WORKDIR/$tdate-$SEARCHTERM.out

head -7 $CURRENTLOG/$LOGFILE.log > $WORKDIR/$tdate-$SEARCHTERM.out

grep $SEARCHTERM $CURRENTLOG/$LOGFILE.log >> $WORKDIR/$tdate-$SEARCHTERM.out

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


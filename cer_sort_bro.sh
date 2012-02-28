#!/usr/local/bin/bash

Today="`date +%m%d%y-%H`"
mkdir /usr/local/bro/logs/certs/test2/$Today



DIR="/usr/local/bro/logs/certs"
SUFFIX="der"

for i in "$DIR"/*.$SUFFIX
do
    blah="`echo ${i%%.$SUFFIX}.der |sed 's#^.*/##'`"
#    echo ${i%%.$SUFFIX}.der
    blah2=`md5 -q /usr/local/bro/logs/certs/$blah`
    blah3=`openssl x509 -inform DER -in /usr/local/bro/logs/certs/$blah -subject | grep subject | sed 's#^.*/##'`
    openssl x509 -inform DER -in /usr/local/bro/logs/certs/$blah -text > "/usr/local/bro/logs/certs/test2/$Today/$blah2.$blah3"

#    openssl x509 -inform DER -in /usr/local/bro/logs/certs/$blah -subject | grep subject | sed 's#^.*/##'
#    openssl x509 -inform DER -in /usr/local/bro/logs/certs/test/$blah -text | grep Subject > "/usr/local/bro/logs/certs/test/$Today/$blah"
#    openssl asn1parse -inform DER -in /usr/local/bro/logs/certs/test/$blah | grep -iE "(OBJECT|PRINTABLESTRING)" | awk '{print $7}' | sort -u >> "/usr/local/bro/logs/certs/test/$Today/$blah"
done


# openssl asn1parse -inform DER -in logs/certs/cert.222.231.61.45-server-c0.der | grep -iE "(OBJECT|PRINTABLESTRING)" | awk '{print $7}' | sort -u
# openssl x509 -inform DER -in logs/certs/cert.199.114.61.38-server-c0.der -text | grep Subject

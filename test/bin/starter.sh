#!/bin/sh

BINDIR=$(dirname $0)

$BINDIR/fcgi.pl 127.0.0.1:9099 256 $BINDIR/../cgi-bin/index.fcgi 1

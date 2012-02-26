#!/usr/bin/perl

################################
#
# fcgi!
#
# (c) 2003, bymer
#
# mail: bymer@infostore.org
#
# Don't remove this, please! ;-)
#
# fcgi.pl 127.0.0.1:10510 256 /path/cgi-bin/index.pl 2

use strict;
use FCGI;

if ($#ARGV != 3)
{
	print "\nUsage: fcgi.pl sock backlog exec count\n\n";
	exit();
}

my $path	= $ARGV[0];
my $backlog	= int($ARGV[1]);
my $exec	= $ARGV[2];
my $count	= int($ARGV[3]);

my $socket = FCGI::OpenSocket($path, $backlog);

if (!$socket)
{
	print "fcgi.pl: failed to create socket!\n";
	exit();
}

for (my $i = 0; $i < $count; $i++)
{
	system("$exec $socket &");
	sleep(1);
}

FCGI::CloseSocket($socket);

exit();

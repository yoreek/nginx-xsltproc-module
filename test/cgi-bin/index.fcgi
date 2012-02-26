#!/usr/bin/perl

use strict;
use warnings;

use CGI::Fast;

my $request;

unless ($ENV{'SERVER_SOFTWARE'}) { # for nginx external fcgi
    $CGI::Fast::Ext_Request = FCGI::Request(
        \*STDIN, \*STDOUT, \*STDERR,
        \%ENV, int($ARGV[0]), 1
    );
}

while (1) {
    $request = CGI::Fast->new();

    my $tmpl = $request->param('tmpl') || 'index';
    my $step = $request->param('step') || 1;

    print "Content-type: application/xml\r\n",
          "X-Xslt-Stylesheet: /template/$tmpl.xslt?step=$step\r\n",
          "\r\n<root />\n";

    $request = undef;
}

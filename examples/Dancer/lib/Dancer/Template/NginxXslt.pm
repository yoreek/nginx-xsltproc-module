package Dancer::Template::NginxXslt;

use strict;
use warnings;

use Dancer::SharedData;
use XML::Hash::XS qw();
use base "Dancer::Template::Abstract";

our $conv = XML::Hash::XS->new(indent => 2);

sub default_tmpl_ext { "xsl" }
sub view_exists      {   1   }

sub view {
    my ($self, $view) = @_;

    my $def_tmpl_ext = $self->config->{extension} || $self->default_tmpl_ext();
    $view .= ".$def_tmpl_ext" if $view !~ /\.\Q$def_tmpl_ext\E$/;

    return '/' . $view;
}

sub render {
    my ($self, $template, $tokens) = @_;

    my $response = Dancer::SharedData->response();

    $response->header('X-Xslt-Stylesheet' => $template);
    $response->header('Content-Type'      => 'application/xml');

    return $conv->hash2xml($tokens);

    return "t: $template";
}

1;

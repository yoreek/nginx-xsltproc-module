package Mojolicious::Plugin::NginxRenderer;

use Mojo::Base 'Mojolicious::Plugin';
use XML::Hash::XS;

use constant EXT => 'xsl';

sub register {
    my ($self, $app) = @_;

    $app->renderer->add_handler(xsl => sub {
        my ($renderer, $c, $output, $options) = @_;

        my $model = $c->stash('model') || {};
        $$output  = hash2xml($model);

        my $path = join('.', $options->{template}, EXT);
        $c->res->headers->header('X-Xslt-Stylesheet' => $path);

        return 1;
    });

    $app->types->type(xml => 'application/xml');
}

1;

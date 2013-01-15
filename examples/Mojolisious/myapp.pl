#!/usr/bin/env perl

use Mojolicious::Lite;
use lib 'lib';

plugin 'NginxRenderer';

app->renderer->default_handler('xsl');
app->renderer->default_format('xml');

get '/' => sub {
    my $self = shift;
    $self->render('index', model => {
        'title'   => 'Index page',
        'content' => 'Index page',
    });
};

get '/test' => sub {
    my $self = shift;
    $self->stash(model => {
        'title'   => 'Test page',
        'content' => 'Test page',
    });
};

get '/empty' => sub {
};

app->start;

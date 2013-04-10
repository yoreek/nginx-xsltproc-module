package myapp;
use Dancer ':syntax';

our $VERSION = '0.1';

set template => 'nginx_xslt', layout => 0, server_tokens => 1;

get '/' => sub {
    template 'index' => { msg => 'Dancer test' };
};

true;

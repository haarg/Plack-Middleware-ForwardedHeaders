use strict;
use warnings;
use Test::More;

use Plack::Middleware::ForwardedHeaders;
use Plack::Test;
use Plack::Builder;

test_psgi
    app => builder {
        enable 'ForwardedHeaders', trusted => '127.0.0.1', style => 'apache';
        sub {
            my $env = shift;
            return [ 200, [
                'Content-Type' => 'text/plain',
                'X-Remote'  => $env->{REMOTE_ADDR},
                'X-Host'    => $env->{HTTP_HOST},
                'X-Scheme'  => $env->{'psgi.url_scheme'},
            ], [ "" ] ],
        };
    },
    client => sub {
        my $cb = shift;
        my $req = HTTP::Request->new(GET => "http://localhost/", [
            'X-Forwarded-For' => '10.10.10.10',
        ]);
        my $res = $cb->($req);
        is $res->header('X-Remote'), '10.10.10.10';
    };
 
done_testing;

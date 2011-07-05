use 5.008;
use strict;
use warnings;
package Plack::Middleware::ForwardedHeaders;
# ABSTRACT: Use forwarded headers from proxy servers
use parent qw(Plack::Middleware);
use Plack::Util::Accessor qw(trusted style scheme host remote);
our $VERSION = 0.001;

sub prepare_app {
    my $self = shift;
    my $style = lc $self->style || 'apache';
    if ($style eq 'apache') {
        $self->scheme('X-Forwarded-Proto')
            unless exists $self->{scheme};
        $self->host('X-Forwarded-Host')
            unless exists $self->{host};
        $self->remote('X-Forwarded-For')
            unless exists $self->{remote};
    }
    elsif ($style eq 'nginx') {
        $self->scheme('X-Forwarded-Proto')
            unless exists $self->{scheme};
        $self->remote('X-Real-IP')
            unless exists $self->{remote};
    }
    for my $h (qw(scheme host remote)) {
        if (my $v = $self->{$h}) {
            $v = uc $v;
            $v =~ s/-/_/g;
            $self->{$h} = $v;
        }
    }
    $self->trusted([$self->trusted])
        unless ref $self->trusted;
    $self->{_trusted} = { map { $_ => 1 } @{ $self->trusted } };
}

sub call {
    my ($self, $env) = @_;
    my $trusted = $self->{_trusted};
    if ($trusted->{ $env->{REMOTE_ADDR} }) {
        if (my $header = $self->scheme) {
            if (my $scheme = $env->{"HTTP_$header"}) {
                if ($header eq 'X_FORWARDED_SSL' || $header eq 'FRONT_END_HTTPS') {
                    $env->{'psgi.url_scheme'} = lc $scheme eq 'on' ? 'https' : 'http';
                }
                else {
                    $env->{'psgi.url_scheme'} = lc $scheme;
                }
            }
        }

        if (my $header = $self->host) {
            if ( my $host = $env->{"HTTP_$header"} ) {
                $env->{HTTP_HOST} = $host;
            }
        }

        if (my $header = $self->remote) {
            if ( my $remote = $env->{"HTTP_$header"} ) {
                if ( $header eq 'X_FORWARDED_FOR') {
                    my @remotes = split /,\s*/, $remote;
                    while ( $remotes[0] && $trusted->{ $remotes[0] }) {
                        $remote = shift @remotes;
                    }
                    $env->{REMOTE_ADDR} = $remotes[0] || $remote;
                }
                else {
                    $env->{REMOTE_ADDR} = $remote;
                }
            }
        }
    }

    $self->app->($env);
}

1;

=head1 SYNOPSIS

    # Use Apache style headers from proxy server on 127.0.0.1
    builder {
        enable 'ForwardedHeaders', trusted => '127.0.0.1', style => 'apache';
        $app;
    };

=head1 DESCRIPTION

This module uses headers sent by a proxy server to correct the
remote address, host, and scheme used.  These headers should only
be used when sent by a trusted proxy.  There is no standard for the
headers used, so they must be configured manually to prevent users
from spoofing them.

=head1 CONFIGURATION

=over 8

=item trusted

A list of IP addresses that are trusted sources.

=item style

Can be set to select a common set of headers used.

=over 4

=item apache

Selects the headers C<X-Forwarded-Host>, C<X-Forwarded-For>, and
C<X-Forwarded-Proto>.  Apache will not set any header for the scheme.

=item nginx

Selects the header C<X-Real-Ip>.

=back

=item scheme

The HTTP header to use to detect the scheme used.  There is no
universal header used for this, and it will need to be configured
explicitly in your proxy server.  If an arbitrary header is set,
it is expected to contain the scheme.  Known headers:

=over 4

=item X-Forwarded-Proto

Used by Amazon Elastic Load Balancer.

=item X-Forwarded-Scheme

Used by WSGIProxy.

=item X-Forwarded-SSL

Should have a value of C<on> to specify HTTPS.  Used by CouchDB.

=item Front-End-HTTPS

Used by Microsoft Internet Security and Acceleration Server.  Should have value of C<on> to specify HTTPS.

=back

=item host

Should be set to the header that will contain the original host requested.  Known headers:

=over 4

=item X-Forwarded-Host

Set by Apache 2.2

=back

=item remote

Should be set to the header that will contain the original requesting address.  Known headers:

=over 4

=item X-Forwarded-For

The de-facto standard for finding the originating client IP address.
Set by Squid, Apache 2.2, and many others.

=item X-Real-IP

Recommended in the nginx documentation, and by the HttpRealIp module by default.

=back

=back

=head1 SEE ALSO

There are other modules with similar goals to this module.

=over 8

=item L<Plack::Middleware::ReverseProxy>

Relies on a Plack::Middleware::Conditional check to determine if the source of the headers is trusted.  Detects which incoming headers to use, which can allow users to fake headers even with the conditional source check.

=item L<Plack::Middleware::XForwardedFor>

Only supports the X-ForwardedFor header.

=back


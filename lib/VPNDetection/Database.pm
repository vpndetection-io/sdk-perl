package VPNDetection::Database;

use strict;
use warnings;

use Carp ();

use VPNDetection::Error;

our $VERSION = '1.0.0';

# The datasets your organization is licensed to download.
sub list {
    my $self = shift;
    $self->_assert_blocking_ok('list');
    return $self->{client}->_wait($self->list_p(@_));
}

sub list_p {
    my ($self, %options) = @_;
    return $self->_body_p('list', \%options, '/api/v1/database/list')
        ->then(sub { $_[0]->{datasets} });
}

# What is inside one dataset: schema, samples, row count and per-format sizes.
sub metadata {
    my $self = shift;
    $self->_assert_blocking_ok('metadata');
    return $self->{client}->_wait($self->metadata_p(@_));
}

sub metadata_p {
    my ($self, $id, %options) = @_;
    Carp::croak('database->metadata: expected a dataset id') if !defined $id || !length $id;
    return $self->_body_p('metadata', \%options, '/api/v1/database/metadata', id => $id);
}

# The digests published alongside one dataset file.
#
# Returns the WHOLE set rather than one algorithm: which digests a dataset
# publishes is the API's choice, not ours, and picking one here is how a caller
# ends up holding undef against a perfectly healthy API.
sub checksums {
    my $self = shift;
    $self->_assert_blocking_ok('checksums');
    return $self->{client}->_wait($self->checksums_p(@_));
}

sub checksums_p {
    my ($self, $id, $format, %options) = @_;
    Carp::croak('database->checksums: expected a dataset id') if !defined $id || !length $id;
    Carp::croak('database->checksums: expected a format') if !defined $format || !length $format;
    return $self->_body_p(
        'checksums', \%options, '/api/v1/database/checksum', id => $id, format => $format,
    )->then(sub { $_[0]->{checksums} });
}

# Your organization's recent download attempts, newest first.
sub downloads {
    my $self = shift;
    $self->_assert_blocking_ok('downloads');
    return $self->{client}->_wait($self->downloads_p(@_));
}

sub downloads_p {
    my ($self, %options) = @_;
    my $limit = delete $options{limit};
    return $self->_body_p(
        'downloads', \%options, '/api/v1/database/downloads',
        defined $limit ? (limit => $limit) : (),
    )->then(sub { $_[0]->{downloads} });
}

# The time-limited URL for one dataset file.
#
# The URL is returned rather than the bytes, so the caller decides how to
# transfer a file that routinely runs to gigabytes. The link authorizes the START
# of a transfer, so one already running is not interrupted when it lapses.
sub download_url {
    my $self = shift;
    $self->_assert_blocking_ok('download_url');
    return $self->{client}->_wait($self->download_url_p(@_));
}

sub download_url_p {
    my ($self, $id, $format, %options) = @_;
    Carp::croak('database->download_url: expected a dataset id') if !defined $id || !length $id;
    Carp::croak('database->download_url: expected a format') if !defined $format || !length $format;
    my $client = $self->{client};
    $client->_check_options('database->download_url', \%options, 'retries');
    my $url = $client->_url('/api/v1/database/download', id => $id, format => $format);
    my $retries = defined $options{retries} ? $options{retries} : $client->{retries};
    return $client->_retry_p($retries, sub {
        $client->_get_p($url)->then(sub {
            my $res = shift->res;
            return _location($res) if $res->code == 302;
            # A 2xx here means the user agent followed the redirect and read the
            # dataset into memory. Naming the cause beats reporting a shape
            # mismatch a caller cannot act on.
            die VPNDetection::Error->new(
                kind => 'server_error', status => $res->code,
                message => 'expected a redirect to object storage but got '
                    . $res->code . '; the user agent must not follow redirects',
            ) if $res->is_success;
            die VPNDetection::Error->from_response($res->code, $res->headers, $res->json);
        });
    });
}

sub _new {
    my ($class, $client) = @_;
    return bless { client => $client }, $class;
}

sub _body_p {
    my ($self, $method, $options, $path, @query) = @_;
    my $client = $self->{client};
    $client->_check_options("database->$method", $options, 'retries');
    my $url = $client->_url($path, @query);
    my $retries = defined $options->{retries} ? $options->{retries} : $client->{retries};
    return $client->_retry_p($retries, sub { $client->_json_p($url) });
}

sub _location {
    my ($res) = @_;
    my $location = $res->headers->location;
    die VPNDetection::Error->new(
        kind => 'server_error', status => $res->code,
        message => 'the API redirected without a Location header',
    ) if !defined $location || !length $location;
    return $location;
}

sub _assert_blocking_ok {
    my ($self, $method) = @_;
    $self->{client}->_assert_blocking_ok("database->$method");
}

1;

__END__

=head1 NAME

VPNDetection::Database - the licensed dataset downloads

=head1 SYNOPSIS

    my $db = $client->database;

    my $datasets = $db->list;
    my $meta = $db->metadata('vpn_ip_extended_v1');
    my $sums = $db->checksums('vpn_ip_extended_v1', 'mmdb');
    my $url = $db->download_url('vpn_ip_extended_v1', 'mmdb');

=head1 DESCRIPTION

Access is granted by contract rather than self-serve, and needs a key carrying
the C<db.download> scope. Reached through L<VPNDetection/database>.

Every method has a C<_p> twin returning a L<Mojo::Promise>, and every method
takes a per-call C<retries> option.

=head1 METHODS

=head2 list

An array reference of the datasets your organization may download.

=head2 metadata($id)

One dataset's document: C<updated>, C<entries>, per-format C<schema>, C<sample>
and C<size>. Poll it to decide whether today's build is worth fetching.

=head2 checksums($id, $format)

The whole digest set for one published file, as a hash reference keyed by
algorithm. Which algorithms appear varies by dataset, so read the one you want
off the hash rather than expecting a fixed set.

=head2 downloads(%options)

Your organization's recent download attempts, newest first. C<limit> caps the
number returned.

=head2 download_url($id, $format)

A time-limited URL for one dataset file. The API answers C<302> and this returns
the C<Location>; the bytes are yours to transfer however suits a file that can
run to gigabytes.

=cut

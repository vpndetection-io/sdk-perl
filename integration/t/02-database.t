use strict;
use warnings;

use lib 't/lib';

use Digest::SHA ();
use File::Temp ();
use Test::More;
use VPNDetectionIntegration::Staging qw(STAGING_HOST client_for);
use VPNDetectionIntegration::Tiers qw(max_rung skip_for);

# The licensed-download half, which only the max key can reach: it is the tier
# holding dataset licenses, and db.download is a scope the other three keys do
# not carry.
#
# The transfer is budgeted before it starts. `metadata` publishes a size per
# format, and that size is checked against the ceiling below FIRST, so a mistaken
# dataset id can never quietly pull one of the gigabyte datasets through CI.

# The max organization licenses cdn_ip for license_type, and at ~10 KB it is
# the only dataset small enough to move in CI.
my $DATASET = 'cdn_ip_v1';
my $FORMAT = 'csvgz';
# 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
# tripping it means the suite is pointed somewhere unintended, which is exactly
# when a transfer must not go ahead.
my $CEILING = 8 * 1024 * 1024;
# A real catalog id the max organization holds no license for.
my $UNLICENSED = 'hosting_ip_v1';

my $reason = skip_for(max_rung());
plan skip_all => $reason if $reason;

my @facts;
my $client = client_for(max_rung(), sub { push @facts, shift });
my $tmp = File::Temp->newdir;
my $transfer;

subtest 'the licensed catalog answers the family shape' => sub {
    my $datasets = $client->database->list;

    ok(@$datasets, 'the max organization licenses something');
    my @ids;
    for my $family (@$datasets) {
        # A license covers a FAMILY, and the ids a download takes hang off
        # `versions`. Before the spec was corrected this list did not exist, so
        # list could not tell a caller what to download.
        ok(length($family->{base} || ''), 'a licensed family carries a base');
        ok(length($family->{name} || ''), "$family->{base} carries a name");
        ok(!exists $family->{docsGroup}, 'docsGroup is a docs-site slug, not API surface');
        ok(!exists $family->{id}, "$family->{base} is keyed by base rather than by a dataset id");
        like($family->{standing}, qr/\A(?:expired|licensed|unlicensed)\z/,
            "$family->{base} carries a documented standing");
        like($family->{license_type}, qr/\A(?:evaluation|standard|redistribute)\z/,
            "$family->{base} carries a documented right");
        ok(defined $family->{in_term}, "$family->{base} says whether the term is live");
        ok(ref $family->{versions} eq 'ARRAY' && @{ $family->{versions} },
            "$family->{base} carries its versions");
        for my $version (@{ $family->{versions} || [] }) {
            ok(length($version->{id} || ''), "$family->{base} has a version with an id");
            ok(ref $version->{formats} eq 'ARRAY' && @{ $version->{formats} },
                "$version->{id} carries its formats");
            push @ids, $version->{id};
        }
    }
    note('licensed: ' . join(', ', @ids));
};

subtest 'a dataset the organization does not license is refused cleanly' => sub {
    my $before = scalar @facts;

    my $url = eval { $client->database->download_url($UNLICENSED, $FORMAT) };

    ok(!defined $url, "$UNLICENSED is not licensed to this organization")
        or diag("$UNLICENSED is now licensed here, so point this at one that is not");
    my $error = $@;
    isa_ok($error, 'VPNDetection::Error', 'the refusal');
    is($error->kind, 'forbidden', 'classified as forbidden');
    is($error->status, 403, 'carrying the status');
    is($error->retryable, 0, 'a license refusal is not worth retrying');
    # The API says which refusal this is (`{"rc":"NOT_LICENSED"}`). Falling back
    # to the status means the client never read the envelope.
    unlike($error->message, qr/\Arequest failed with status/,
        'and the API rc rather than the client fallback');
    is(scalar(@facts) - $before, 1, 'a 4xx is raised once and never retried');
};

subtest 'a real dataset is transferred to disk intact' => sub {
    my $dl = transferred();

    cmp_ok($dl->{written}, '>', 0, 'something was transferred');
    is(-s $dl->{path}, $dl->{written}, 'the file is the length the method reported');
    ok(!-e "$dl->{path}.part", 'the .part file did not outlive a successful transfer');
    open my $fh, '<', $dl->{path} or die "reading the download back: $!";
    binmode $fh;
    my $body = do { local $/; <$fh> };
    is(substr($body, 0, 2), "\x1f\x8b", 'the payload is gzip');

    # The published digests nest under `checksums`; reading a top-level sha256
    # returns nothing against a perfectly healthy API.
    like($dl->{checksums}{sha256}, qr/\A[0-9a-f]{64}\z/,
        'the checksums unwrapped past the envelope');
    is(Digest::SHA::sha256_hex($body), $dl->{checksums}{sha256},
        'and the bytes on disk are the published file');

    # The presigned URL authorizes itself, so the request that follows the 302
    # must carry no credential.
    my @storage = grep { $_->{host} ne STAGING_HOST } @facts;
    ok(@storage, 'object storage was reached, so a 302 was followed');
    is(scalar(grep { $_->{carried_key} } @storage), 0,
        'and the API key was never sent to object storage');
};

subtest 'the bytes variant agrees with the streamed copy' => sub {
    my $dl = transferred();

    my $bytes = $client->database->download_bytes($DATASET, $FORMAT);

    is(length $bytes, $dl->{written}, 'the in-memory copy is the same length');
    is(Digest::SHA::sha256_hex($bytes), $dl->{checksums}{sha256},
        'and hashes to what the API publishes');
};

# Memoized, so the two transfer tests share one download rather than pulling the
# dataset twice each.
sub transferred {
    return $transfer if $transfer;

    my $meta = $client->database->metadata($DATASET);
    is($meta->{id}, $DATASET, 'metadata answered about the dataset asked for');
    my $size = $meta->{size}{$FORMAT};
    ok(defined $size && $size > 0, "$DATASET publishes a $FORMAT size to check a transfer against");
    cmp_ok($size, '<=', $CEILING, "$DATASET is under the ceiling, so it is safe to transfer");
    BAIL_OUT("$DATASET is $size bytes, past the $CEILING ceiling") if !$size || $size > $CEILING;

    # The failure is reported rather than thrown: a transfer that dies takes the
    # rest of the file with it, and `Dubious, test returned 255` says nothing
    # about which of the API, the link and object storage refused.
    my $path = $tmp->dirname . "/$DATASET.csv.gz";
    my $written = eval { $client->database->download($DATASET, $FORMAT, $path) };
    BAIL_OUT("downloading $DATASET.$FORMAT: $@") unless defined $written;
    # Read after the transfer, so a rebuild between the two calls shows up as a
    # digest mismatch rather than passing against a digest of nothing.
    my $checksums = eval { $client->database->checksums($DATASET, $FORMAT) };
    BAIL_OUT("reading the checksums for $DATASET.$FORMAT: $@") unless $checksums;
    note("$DATASET.$FORMAT: $written bytes, metadata says $size");

    return $transfer = { written => $written, path => $path, checksums => $checksums };
}

done_testing();

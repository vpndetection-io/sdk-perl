package VPNDetectionIntegration::Staging;

use strict;
use warnings;

use Cwd ();
use Exporter 'import';
use File::Basename ();
use Mojo::UserAgent;
use Test::More;
use VPNDetection;

use VPNDetectionIntegration::Tiers qw(key_for observable_rungs);

our @EXPORT_OK = qw(
    %MEMBERS PROBE STAGING STAGING_HOST
    answer_for assert_served_by_tier assert_shape client_for ladder_skip
);

# The staging fixtures the test files share: one client per tier, one lookup per
# tier, and the shape rules that hold whatever the plan.

use constant STAGING => 'https://api-staging.vpndetection.io';
use constant STAGING_HOST => 'api-staging.vpndetection.io';

# A stable VPN address, and the one the README teaches.
use constant PROBE => '45.83.91.1';

# One entry per dataset the API answers about. `required` is what a POPULATED
# detail object carries on every tier; `optional` is the max-only remainder,
# which is absent rather than empty on a lower plan.
my @CLASS_KEYS = qw(provider confidence last_seen);
my @PROXY_KEYS = qw(provider first_seen last_seen hits hits_days_pct providers_num);
our %MEMBERS = (
    vpn => { required => ['provider', 'last_seen'], optional => ['confidence', 'method'] },
    hosting => { required => \@CLASS_KEYS, optional => [] },
    relay => { required => \@CLASS_KEYS, optional => [] },
    tor => { required => \@CLASS_KEYS, optional => [] },
    cdn => { required => \@CLASS_KEYS, optional => [] },
    resproxy => { required => \@PROXY_KEYS, optional => [] },
    dcproxy => { required => \@PROXY_KEYS, optional => [] },
    mobproxy => { required => \@PROXY_KEYS, optional => [] },
);

# This suite exists to exercise the distribution as PUBLISHED, and the way it
# fails to is silent: with the working tree in @INC every test passes, against
# code that was never released. Checked at load, so `prove` run by hand refuses
# just as scripts/run.pl does.
assert_published();

sub assert_published {
    my $repo = File::Basename::dirname(_root());
    my $loaded = $INC{'VPNDetection.pm'};
    die "VPNDetection is not loaded, so there is nothing published to test\n" unless $loaded;

    # Only when the working tree is actually there to be picked up: run.sh mounts
    # the integration directory alone, and there is nothing to refuse then.
    return unless -e "$repo/lib/VPNDetection.pm";
    for my $path (Cwd::abs_path($loaded), map { Cwd::abs_path($_) || $_ } @INC) {
        next unless $path =~ m{\A\Q$repo\E/(?:lib|blib)(?:/|\z)};
        die "$path is the working tree, and this suite must test the published "
            . "distribution; run scripts/run.pl\n";
    }
    diag("testing VPNDetection $VPNDetection::VERSION from $loaded");
}

# What a test is allowed to remember about a request it made.
#
# Only derived facts leave here. A failing assertion prints its operands, so
# holding on to the request itself is how a key ends up in a public CI log:
# whether the key was carried is a boolean, and the caller never sees the key.
sub facts_for {
    my ($req, $key) = @_;
    my $carried = 0;
    if (length $key) {
        my $query = $req->url->query->to_string;
        $carried = 1 if index($query, $key) >= 0;
        my $headers = $req->headers->to_hash;
        for my $value (values %$headers) {
            $carried = 1 if !ref $value && index($value, $key) >= 0;
        }
    }
    # A POST /batch carries its addresses in the body, so the path alone no longer
    # says what was asked about.
    my $body = $req->json;
    my $ips = ref $body eq 'HASH' && ref $body->{ips} eq 'ARRAY' ? [@{ $body->{ips} }] : [];
    return {
        host => $req->url->host, path => $req->url->path->to_string, ips => $ips,
        carried_key => $carried,
    };
}

sub client_for {
    my ($rung, $on_request) = @_;
    my $key = key_for($rung);
    my $ua = Mojo::UserAgent->new;
    $ua->on(start => sub {
        my (undef, $tx) = @_;
        $on_request->(facts_for($tx->req, $key)) if $on_request;
    });
    return VPNDetection->new(
        base_url => STAGING,
        ua => $ua,
        length $key ? (api_key => $key) : (),
    );
}

# One lookup per tier for the whole run. The client caches, so a second reader of
# the same tier would cost no request either, but the fixture also carries what
# the wire said, which the client does not keep.
my %ANSWERS;

sub answer_for {
    my ($rung) = @_;
    return $ANSWERS{ $rung->{tier} } if $ANSWERS{ $rung->{tier} };

    my @facts;
    my $client = client_for($rung, sub { push @facts, shift });
    # Reported rather than thrown: a lookup that dies takes the rest of the file
    # with it, and the exit status alone says nothing about which tier failed.
    my $result = eval { $client->lookup(PROBE) };
    BAIL_OUT("looking " . PROBE . " up on the $rung->{tier} tier: $@") unless $result;
    my $carried = grep { $_->{carried_key} } @facts;
    return $ANSWERS{ $rung->{tier} } = {
        rung => $rung, result => $result, carried_key => $carried ? 1 : 0,
    };
}

sub assert_served_by_tier {
    my ($fixture) = @_;
    my $tier = $fixture->{rung}{tier};
    is($fixture->{result}->ip, PROBE, "$tier: answered about the address asked for");
    is($fixture->{result}->is_bogon, 0, "$tier: a served answer is not a local one");
    if (defined $fixture->{rung}{secret}) {
        # Without this the tier is indistinguishable from an unauthenticated one,
        # and every comparison the ladder makes against it is vacuous.
        is($fixture->{carried_key}, 1, "$tier: the key reached the wire");
    }
    assert_shape($fixture->{result}, $tier);
}

# Holds on every plan: presence is the plan, the value is the answer.
#
# Read off the wire body, then cross-checked against the reader. That pairing is
# the positive half of the absent-versus-false contract: a field the plan DOES
# include must survive the mapping, false and all.
sub assert_shape {
    my ($r, $tier) = @_;
    my $raw = $r->raw;
    ok(defined $raw->{ip} && !ref $raw->{ip}, "$tier: ip is a string");
    ok(exists $raw->{is_vpn}, "$tier: is_vpn is on every plan");
    ok(defined $r->is_vpn, "$tier: and the client maps it");

    for my $name (sort keys %MEMBERS) {
        my $flag = "is_$name";
        if (exists $raw->{$flag}) {
            is($r->has($flag), 1, "$tier: $flag is served, so the plan carries it");
            ok(defined $r->$flag, "$tier: and it reads as 0 or 1, never undef");
        }
        next unless exists $raw->{$name};
        # A detail object without its flag would leave a caller reading the object
        # to find out whether the address is flagged at all.
        is($r->has($flag), 1, "$tier: $name is served with $flag");
        assert_detail($r, $name, $tier);
    }
}

sub assert_detail {
    my ($r, $name, $tier) = @_;
    my $detail = $r->raw->{$name};
    is(ref $detail, 'HASH', "$tier: $name is an object when present");
    return unless ref $detail eq 'HASH';

    my $flag = "is_$name";
    if (!keys %$detail) {
        is($r->$flag, 0, "$tier: $name is empty, so $flag is false");
        return;
    }
    my $spec = $MEMBERS{$name};
    my %documented = map { $_ => 1 } @{ $spec->{required} }, @{ $spec->{optional} };
    for my $key (@{ $spec->{required} }) {
        ok(exists $detail->{$key}, "$tier: $name is populated and carries $key");
    }
    for my $key (sort keys %$detail) {
        ok($documented{$key}, "$tier: $name.$key is a documented key of this detail object");
    }
}

# The ladder needs two rungs to say anything. The unauthenticated one is always
# there, so this only fires when no tier secret at all is configured.
sub ladder_skip {
    return undef if scalar(observable_rungs()) > 1;
    return 'no tier secret is set, so there is no ladder to compare';
}

sub _root {
    return Cwd::abs_path(File::Basename::dirname(__FILE__) . '/../../..');
}

1;

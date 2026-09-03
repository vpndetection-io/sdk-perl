use strict;
use warnings;

use Test::More;
use VPNDetection;

# Hits production, so it costs quota and is skipped by default:
#
#   VPNDETECTION_LIVE=1 ./scripts/test.sh t/04-live.t
#
# It exists for the one claim a stub cannot make honestly: that the free tier
# really does omit the tier-gated fields rather than answering false.
plan skip_all => 'set VPNDETECTION_LIVE=1 to run the live checks'
    unless $ENV{VPNDETECTION_LIVE};

my $client = VPNDetection->new(
    $ENV{VPNDETECTION_API_KEY} ? (api_key => $ENV{VPNDETECTION_API_KEY}) : (),
);

subtest 'a known VPN address' => sub {
    my $result = $client->lookup('45.83.91.1');
    is($result->ip, '45.83.91.1', 'the address comes back normalized');
    is($result->is_vpn, 1, 'flagged as VPN infrastructure');
    is($result->is_bogon, 0, 'served rather than computed');
};

subtest 'an ordinary public address on the free tier' => sub {
    plan skip_all => 'a key raises the plan, so the free shape no longer applies'
        if $ENV{VPNDETECTION_API_KEY};

    my $result = $client->lookup('1.1.1.1');
    is($result->is_vpn, 0, 'not VPN infrastructure');
    is($result->has('is_hosting'), 0, 'the hosting flag is ABSENT without a key');
    is($result->is_hosting, undef, 'so it reads as undef, not as false');
    is($result->is_hosting // 0, 0, 'and as false only when you ask for that');
    is_deeply([sort keys %{ $result->raw }], ['ip', 'is_vpn'], 'the free tier answers two fields');
};

subtest 'a batch mixes served and local answers' => sub {
    my $answers = $client->lookup_batch(['45.83.91.1', '10.0.0.1', '45.83.91.1']);
    is(scalar keys %$answers, 2, 'the duplicate collapsed');
    is($answers->{'45.83.91.1'}->is_vpn, 1, 'the served answer');
    is($answers->{'10.0.0.1'}->is_bogon, 1, 'the local answer');
};

done_testing();

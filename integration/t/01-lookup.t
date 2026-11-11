use strict;
use warnings;

use lib 't/lib';

use Mojo::UserAgent;
use Test::More;
use VPNDetection;
use VPNDetectionIntegration::Staging qw(
    %MEMBERS PROBE STAGING answer_for assert_served_by_tier client_for ladder_skip
);
use VPNDetectionIntegration::Tiers qw(@RUNGS observable_rungs paid_rung skip_for trial_rung unauth_rung);

# The published distribution looking addresses up against the staging API.
#
# Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each one
# serving a superset of the tier below it, so a pricing change stays a pricing
# change instead of arriving as a red SDK build. What a served answer must
# satisfy on every tier: ip and is_vpn always; a served flag reads as 0 or 1
# rather than undef; a field a higher tier serves is ABSENT on a lower one rather
# than false; a populated detail object carries its documented keys; an empty one
# means its flag is false.

subtest 'a lookup without a key answers ip and is_vpn at the least' => sub {
    my $fixture = answer_for(unauth_rung());

    is($fixture->{result}->raw->{ip}, PROBE, 'the wire answered about the address asked for');
    ok(exists $fixture->{result}->raw->{is_vpn}, 'and carries is_vpn');
    assert_served_by_tier($fixture);
    diag('testing against ' . STAGING);
};

subtest 'a key reaches the wire and its answer keeps its shape' => sub {
    my @keyed = grep { defined $_->{secret} } @RUNGS;
    note("skipped $_->{tier}: " . skip_for($_)) for grep { skip_for($_) } @keyed;

    my @observable = grep { !skip_for($_) } @keyed;
    plan skip_all => 'no staging key is set, so no keyed tier can be exercised' unless @observable;

    assert_served_by_tier(answer_for($_)) for @observable;
};

subtest 'each tier serves a superset of the tier below' => sub {
    my $skip = ladder_skip();
    plan skip_all => $skip if $skip;

    my $below;
    for my $rung (observable_rungs()) {
        # trial_expired marks a free-plan key's answers, and no other: it is not
        # a field a tier serves.
        my @fields = sort grep { $_ ne 'trial_expired' } keys %{ answer_for($rung)->{result}->raw };
        note("$rung->{tier}: " . scalar(@fields) . ' fields');
        if ($below) {
            my %served = map { $_ => 1 } @fields;
            for my $field (@{ $below->{fields} }) {
                ok($served{$field}, "$rung->{tier} keeps $field, which $below->{tier} serves");
            }
            # Without this a run in which every key resolved to the same plan
            # would pass: identical sets satisfy containment in both directions.
            if ($rung->{widens}) {
                cmp_ok(scalar @fields, '>', scalar @{ $below->{fields} },
                    "$rung->{tier} answers more fields than $below->{tier}");
            }
        }
        $below = { tier => $rung->{tier}, fields => \@fields } unless $rung->{tier} eq 'trial';
    }
};

subtest "a free-plan key's answer is a paid one or Unlimited's, and says which" => sub {
    plan skip_all => skip_for(trial_rung()) if skip_for(trial_rung());

    my $raw = answer_for(trial_rung())->{result}->raw;

    ok(exists $raw->{trial_expired}, 'a free-plan key answers trial_expired');
    # The organization's first 100 lookups of the UTC day are answered in full,
    # and the rest as Unlimited's: which half a run sees depends on the day.
    is(exists $raw->{is_hosting} ? 1 : 0, $raw->{trial_expired} ? 0 : 1,
        'is_hosting is served exactly while the day lasts');
};

subtest "a free-plan key's batch of two is refused as a bad request, once" => sub {
    plan skip_all => skip_for(trial_rung()) if skip_for(trial_rung());
    my @paths;
    my $client = client_for(trial_rung(), sub { push @paths, shift->{path} });

    my $answers = $client->lookup_batch([PROBE, '8.8.8.8']);

    for my $ip (PROBE, '8.8.8.8') {
        my $refused = $answers->{$ip};
        isa_ok($refused, 'VPNDetection::Error', "$ip in a free-plan key's batch of two");
        is($refused->kind, 'bad_request', 'is refused as a bad request');
        is($refused->status, 402, 'with a 402');
        ok(!$refused->retryable, 'which is not retryable');
    }
    is_deeply(\@paths, ['/batch'], 'one request, never retried');
};

subtest "a free-plan key's batch of one is answered" => sub {
    plan skip_all => skip_for(trial_rung()) if skip_for(trial_rung());

    my $answer = client_for(trial_rung())->lookup_batch([PROBE])->{+PROBE};

    isa_ok($answer, 'VPNDetection::Result', PROBE);
    ok(exists $answer->raw->{trial_expired}, 'and says whether the trial day is spent');
};

subtest 'a field a higher tier serves is absent on a lower one, never false' => sub {
    my $skip = ladder_skip();
    plan skip_all => $skip if $skip;

    my @rungs = observable_rungs();
    my @fixtures = map { answer_for($_) } @rungs;
    my $compared = 0;

    for my $i (0 .. $#fixtures) {
        my $lower = $fixtures[$i]{result};
        my %above;
        for my $higher (@fixtures[$i + 1 .. $#fixtures]) {
            $above{$_} = 1 for keys %{ $higher->{result}->raw };
        }
        for my $field (sort keys %above) {
            next if exists $lower->raw->{$field};
            # A field the client does not model at all is the API moving ahead of
            # the pinned spec, not a plan dropping something.
            next unless eval { $lower->has($field); 1 };
            # undef, 0 and '' are all false in Perl, which is exactly why this is
            # asserted on PRESENCE rather than on the value.
            is($lower->has($field), 0,
                "$field is not in the $rungs[$i]{tier} plan, so the plan does not carry it");
            is($lower->$field, undef, "and $field reads as undef rather than as false");
            $compared++;
        }
    }

    # Every tier answering the same fields makes this a no-op, which is what a
    # run whose keys all resolved to one plan looks like. Say so rather than
    # passing on nothing.
    plan skip_all => 'no observable tier serves a field another one lacks' unless $compared;
    note("$compared absent field(s) checked across the ladder");
};

subtest 'a bogon is answered without touching the network' => sub {
    my $offline = VPNDetection->new(base_url => STAGING, ua => refusing_ua());

    my $result = $offline->lookup('10.0.0.1');

    is($result->is_bogon, 1, 'a private address is answered locally');
    is($result->is_vpn, 0, 'and cannot be VPN infrastructure');
    is(VPNDetection::is_bogon('10.0.0.1'), 1, 'the exportable form agrees with the client');
    # Computed rather than served, so it carries every field whatever the plan.
    for my $name (sort keys %MEMBERS) {
        my $flag = "is_$name";
        is($result->$flag, 0, "$flag is present and false on a bogon");
        is_deeply($result->$name, {}, "$name is present and empty on a bogon");
    }
};

subtest 'a batch without a key is refused once, and its bogon still answered' => sub {
    my @paths;
    my $client = client_for(unauth_rung(), sub { push @paths, shift->{path} });

    my $answers = $client->lookup_batch([PROBE, '10.0.0.1']);

    is($answers->{'10.0.0.1'}->is_bogon, 1, 'the private address was answered locally');
    my $refused = $answers->{+PROBE};
    isa_ok($refused, 'VPNDetection::Error', 'a batch without a key');
    is($refused->kind, 'unauthorized', 'is refused as unauthorized');
    is($refused->status, 401, 'with a 401');
    ok(!$refused->retryable, 'which is not retryable');
    is_deeply(\@paths, ['/batch'], 'one request, never retried');
};

subtest 'a batch collapses duplicates and keeps bogons off the wire' => sub {
    # A batch needs a paid plan, and starter is the cheapest.
    plan skip_all => skip_for(paid_rung()) if skip_for(paid_rung());
    my (%asked, $carried);
    $carried = 1;
    my $client = client_for(paid_rung(), sub {
        my $fact = shift;
        $asked{ join ' ', $fact->{path}, join ',', @{ $fact->{ips} } } = 1;
        $carried &&= $fact->{carried_key};
    });

    my @wanted = (PROBE, '8.8.8.8', '10.0.0.1');
    my $answers = $client->lookup_batch([PROBE, '8.8.8.8', PROBE, '10.0.0.1', '8.8.8.8']);

    is_deeply([sort keys %$answers], [sort @wanted], 'three addresses answered from five');
    # Distinct requests rather than a call count, so a retry against a wobbling
    # staging cannot read as a failure to deduplicate.
    is_deeply([keys %asked], ['/batch ' . PROBE . ',8.8.8.8'],
        'and only the two servable ones reached the API, in one POST /batch');
    ok($carried, 'the paid key reached the wire');
    is($answers->{'10.0.0.1'}->is_bogon, 1, 'the private address was answered locally');
    for my $ip (PROBE, '8.8.8.8') {
        isa_ok($answers->{$ip}, 'VPNDetection::Result', $ip);
    }
};

# Fails every request, so anything reaching the network is loud about it rather
# than merely slow.
sub refusing_ua {
    my $ua = Mojo::UserAgent->new;
    $ua->on(start => sub { die "the bogon path reached the network\n" });
    return $ua;
}

done_testing();

use strict;
use warnings;

use lib 't/lib';

use Test::More;
use VPNDetection;
use VPNDetection::Error;
use VPNDetectionTest;
use VPNDetectionTest::Origin;

# The shared conformance corpus, asserted by every VPNDetection SDK in the same
# terms, so a Perl-only drift fails here rather than surfacing as two client
# libraries quietly disagreeing about one address.
my $corpus = VPNDetectionTest::corpus();

my %routes;
my $origin = VPNDetectionTest::Origin->new(sub {
    my ($c) = @_;
    my $route = $routes{ $c->req->url->path->to_string };
    return $c->render(json => { error => 'not a valid IP address' }, status => 400)
        unless $route;
    $c->res->headers->header($_ => $route->{headers}{$_}) for keys %{ $route->{headers} || {} };
    $c->render(json => $route->{body}, status => $route->{status} || 200);
});

sub client {
    return VPNDetection->new(base_url => $origin->url, @_);
}

sub serve {
    %routes = ();
    for my $route (@_) {
        $routes{"/$route->{ip}"} = $route;
    }
    $origin->reset;
}

subtest 'a bogon is answered locally in the full max shape' => sub {
    serve();
    my $result = client()->lookup('10.0.0.1');

    is($result->ip, '10.0.0.1', 'the address comes back');
    is($result->is_bogon, 1, 'marked as computed rather than served');
    for my $flag (@{ $corpus->{bogonResponse}{flagsFalse} }) {
        ok($result->has($flag), "$flag is present");
        is($result->$flag, 0, "$flag is false");
    }
    for my $object (@{ $corpus->{bogonResponse}{emptyObjects} }) {
        ok($result->has($object), "$object is present");
        is_deeply($result->$object, {}, "$object is empty");
    }
    is($origin->count, 0, 'a bogon must not reach the network');
};

subtest 'lookup preserves absent-versus-false across every plan shape' => sub {
    for my $case (@{ $corpus->{lookup} }) {
        serve({ ip => $case->{body}{ip}, status => $case->{status}, body => $case->{body} });
        my $result = client()->lookup($case->{body}{ip});
        my $expect = $case->{expect};

        is($result->ip, $expect->{ip}, "$case->{name}: ip");
        is($result->is_bogon, $expect->{isBogon} ? 1 : 0, "$case->{name}: is_bogon");

        for my $field (sort keys %{ $expect->{present} || {} }) {
            my $want = $expect->{present}{$field} ? 1 : 0;
            ok($result->has($field), "$case->{name}: $field was served");
            is($result->$field, $want, "$case->{name}: $field is $want");
        }
        for my $field (@{ $expect->{absent} || [] }) {
            is($result->has($field), 0, "$case->{name}: $field is ABSENT, not false");
            is($result->$field, undef, "$case->{name}: $field reads as undef");
            ok(!exists $result->{$field}, "$case->{name}: $field has no key at all");
        }
        for my $field (@{ $expect->{emptyPresent} || [] }) {
            ok($result->has($field), "$case->{name}: $field was served");
            is_deeply($result->$field, {}, "$case->{name}: $field is present and empty");
        }
        for my $object (qw(vpn hosting dcproxy)) {
            next unless $expect->{$object};
            is_deeply($result->$object, $expect->{$object}, "$case->{name}: $object");
        }
    }
};

subtest 'a 429 is classified by Retry-After, not by its status' => sub {
    for my $case (@{ $corpus->{errors} }) {
        serve({
            ip => '1.1.1.1', status => $case->{status},
            body => $case->{body}, headers => $case->{headers},
        });
        # No retries, so a retryable failure surfaces rather than looping.
        my $result = eval { client(retries => 0)->lookup('1.1.1.1') };
        my $error = $@;

        ok(!defined $result, "$case->{name}: the call failed");
        isa_ok($error, 'VPNDetection::Error', "$case->{name}: error type");
        is($error->kind, $case->{expect}{kind}, "$case->{name}: kind");
        is($error->retryable, $case->{expect}{retryable} ? 1 : 0, "$case->{name}: retryable");
        is($error->message, $case->{expect}{message}, "$case->{name}: message")
            if defined $case->{expect}{message};
        is($error->retry_after, $case->{expect}{retryAfterSeconds}, "$case->{name}: retry_after")
            if defined $case->{expect}{retryAfterSeconds};
    }
};

subtest 'batch dedupes, short-circuits bogons and keys by address' => sub {
    my $case = VPNDetectionTest::batch_case('dedup-bogon-and-order-free-keying');
    serve(
        { ip => '1.1.1.1', body => { ip => '1.1.1.1', is_vpn => \0 } },
        { ip => '8.8.8.8', body => { ip => '8.8.8.8', is_vpn => \0 } },
    );
    my $answers = client()->lookup_batch($case->{input});

    # Perl hashes carry no insertion order, so the corpus's key claim is a SET.
    is_deeply([sort keys %$answers], [sort @{ $case->{expect}{keys} }], 'keyed by address');
    is($origin->count, $case->{expect}{httpRequests}, 'duplicates collapsed to one request');
    for my $ip (@{ $case->{expect}{bogonKeys} }) {
        is($answers->{$ip}->is_bogon, 1, "$ip was answered locally");
    }
};

subtest 'one bad address does not lose the rest of the batch' => sub {
    my $case = VPNDetectionTest::batch_case('partial-failure-does-not-fail-the-batch');
    serve({ ip => '1.1.1.1', body => { ip => '1.1.1.1', is_vpn => \0 } });
    my $answers = client(retries => 0)->lookup_batch($case->{input});

    is_deeply([sort keys %$answers], [sort @{ $case->{expect}{keys} }], 'every address is keyed');
    for my $ip (@{ $case->{expect}{errorKeys} }) {
        isa_ok($answers->{$ip}, 'VPNDetection::Error', "$ip carries its error");
    }
    is($answers->{'1.1.1.1'}->is_vpn, 0, 'the good address still answered');
};

subtest 'a cache hit issues no second request' => sub {
    my $case = VPNDetectionTest::batch_case('cache-hit-issues-no-second-request');
    serve({ ip => '1.1.1.1', body => { ip => '1.1.1.1', is_vpn => \0 } });
    my $client = client();
    $client->lookup_batch($case->{input}) for 1 .. $case->{repeat};

    is($origin->count, $case->{expect}{httpRequests}, 'the second batch was served from cache');
};

subtest 'two clients never share a cached answer' => sub {
    serve({ ip => '1.1.1.1', body => { ip => '1.1.1.1', is_vpn => \0 } });
    client(api_key => 'key-a')->lookup('1.1.1.1');
    client(api_key => 'key-b')->lookup('1.1.1.1');

    # Two keys can be on different plans and so entitled to different fields; a
    # shared cache would serve one of them the other's shape.
    is($origin->count, 2, 'each client asked for itself');
};

subtest 'caching can be turned off' => sub {
    serve({ ip => '1.1.1.1', body => { ip => '1.1.1.1', is_vpn => \0 } });
    my $client = client(cache_size => 0);
    $client->lookup('1.1.1.1');
    $client->lookup('1.1.1.1');

    is($origin->count, 2, 'cache_size 0 disables the cache');
};

subtest 'an error is never cached' => sub {
    serve({ ip => '1.1.1.1', status => 500, body => { error => 'lookup failed' } });
    my $client = client(retries => 0);
    eval { $client->lookup('1.1.1.1') };
    eval { $client->lookup('1.1.1.1') };

    is($origin->count, 2, 'the second call asked again');
};

done_testing();

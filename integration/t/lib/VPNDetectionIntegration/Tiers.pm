package VPNDetectionIntegration::Tiers;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(@RUNGS unauth_rung trial_rung paid_rung max_rung key_for skip_for observable_rungs);

# Which plan tiers this run can observe, and the secret each one needs.
#
# Loaded by scripts/run.pl as well as by the tests, so it must not touch the
# distribution under test: the runner reads the tier table BEFORE cpanm has put
# anything in local/.
#
# A tier is observable only when its secret holds something non-empty. Actions
# interpolates a secret that does not exist to an EMPTY STRING rather than
# leaving the variable unset, and a client built with an empty key sends no
# credential at all, so an empty key runs as a second unauthenticated client and
# every comparison against it is vacuously true.

# Ascending, one rung per plan tier. `widens` is what the rung promises against
# whichever observable rung sits below it: the first paid tier serves strictly
# more than no key; every paid plan answers the same fields, so a higher paid
# tier only keeps what the one under it serves. The trial rung's key is on the
# free plan: its answer is a paid one for its organization's daily trial, the
# first 100 lookups of the UTC day, and Unlimited's after, so it promises
# nothing and is never the rung a later one is compared against.
#
# Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
# turns a pricing change into a red SDK build; the relation between the tiers is
# what the client actually has to keep.
our @RUNGS = (
    { tier => 'unauth', secret => undef, widens => 0 },
    { tier => 'trial', secret => 'VPNDETECTION_STAGING_KEY_FREE', widens => 0 },
    { tier => 'starter', secret => 'VPNDETECTION_STAGING_KEY_STARTER', widens => 1 },
    { tier => 'scale', secret => 'VPNDETECTION_STAGING_KEY_SCALE', widens => 0 },
    { tier => 'max', secret => 'VPNDETECTION_STAGING_KEY_MAX', widens => 0 },
);

sub unauth_rung {
    return $RUNGS[0];
}

sub trial_rung {
    return $RUNGS[1];
}

# The cheapest rung a batch can run on: POST /batch needs a paid plan.
sub paid_rung {
    return $RUNGS[2];
}

sub max_rung {
    return $RUNGS[-1];
}

sub key_for {
    my ($rung) = @_;
    return '' unless defined $rung->{secret};
    my $key = defined $ENV{ $rung->{secret} } ? $ENV{ $rung->{secret} } : '';
    $key =~ s/^\s+|\s+\z//g;
    return $key;
}

# A reason to skip, or undef when the rung can be exercised.
sub skip_for {
    my ($rung) = @_;
    return undef if !defined $rung->{secret} || length key_for($rung);
    return "$rung->{secret} is not set, so the $rung->{tier} tier cannot be exercised";
}

sub observable_rungs {
    return grep { !defined skip_for($_) } @RUNGS;
}

1;

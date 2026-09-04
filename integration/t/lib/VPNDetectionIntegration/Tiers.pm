package VPNDetectionIntegration::Tiers;

use strict;
use warnings;

use Exporter 'import';

our @EXPORT_OK = qw(@RUNGS unauth_rung max_rung key_for skip_for observable_rungs);

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
# whichever observable rung sits below it: a paid tier serves strictly more than
# the tier under it, while a free key and no key at all are the same entitlement
# reached two ways.
#
# Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
# turns a pricing change into a red SDK build; the relation between the tiers is
# what the client actually has to keep.
our @RUNGS = (
    { tier => 'unauth', secret => undef, widens => 0 },
    { tier => 'free', secret => 'VPNDETECTION_STAGING_KEY_FREE', widens => 0 },
    { tier => 'starter', secret => 'VPNDETECTION_STAGING_KEY_STARTER', widens => 1 },
    { tier => 'scale', secret => 'VPNDETECTION_STAGING_KEY_SCALE', widens => 1 },
    { tier => 'max', secret => 'VPNDETECTION_STAGING_KEY_MAX', widens => 1 },
);

sub unauth_rung {
    return $RUNGS[0];
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

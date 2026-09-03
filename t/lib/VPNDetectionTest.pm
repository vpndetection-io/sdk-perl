package VPNDetectionTest;

use strict;
use warnings;

use Mojo::File 'path';
use Mojo::JSON 'decode_json';

# The language-neutral conformance corpus, generated into every VPNDetection SDK
# so a binding that drifts fails its own suite.
sub corpus {
    my $root = path(__FILE__)->to_abs->dirname->dirname->dirname;
    return decode_json($root->child('testdata', 'testdata.json')->slurp);
}

sub lookup_case {
    my ($name) = @_;
    my ($case) = grep { $_->{name} eq $name } @{ corpus()->{lookup} };
    die "no lookup case named '$name'" unless $case;
    return $case;
}

sub batch_case {
    my ($name) = @_;
    my ($case) = grep { $_->{name} eq $name } @{ corpus()->{batch} };
    die "no batch case named '$name'" unless $case;
    return $case;
}

1;

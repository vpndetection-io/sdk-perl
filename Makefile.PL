use strict;
use warnings;

use ExtUtils::MakeMaker;

my %args = (
    NAME => 'VPNDetection',
    VERSION_FROM => 'lib/VPNDetection.pm',
    ABSTRACT => 'Official Perl client library for the VPNDetection API',
    AUTHOR => 'Mslm Dev <support@vpndetection.io>',
    LICENSE => 'mit',
    MIN_PERL_VERSION => '5.022',
    PREREQ_PM => {
        # The whole HTTP stack, the JSON codec, the event loop and the promises,
        # from one distribution with no non-core dependencies of its own.
        'Mojolicious' => '9.00',
        # Mojolicious makes TLS optional; the API is HTTPS only, so we do not.
        'IO::Socket::SSL' => '2.009',
    },
    TEST_REQUIRES => {
        'Test::More' => '0.98',
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        keywords => [qw(
            vpn vpn-detection proxy-detection tor ip-intelligence
            fraud-prevention residential-proxy hosting cdn relay
        )],
        resources => {
            homepage => 'https://vpndetection.io',
            repository => {
                type => 'git',
                url => 'https://github.com/vpndetection-io/sdk-perl.git',
                web => 'https://github.com/vpndetection-io/sdk-perl',
            },
            bugtracker => {
                web => 'https://github.com/vpndetection-io/sdk-perl/issues',
            },
        },
        no_index => {
            directory => ['t'],
        },
    },
    test => { TESTS => 't/*.t' },
    clean => { FILES => 'VPNDetection-*' },
);

# The perl 5.22 the distribution declares ships an ExtUtils::MakeMaker
# which does not know TEST_REQUIRES and warns about it. Folding it into
# PREREQ_PM there costs nothing, since Test::More is core on every perl this
# runs on, and it keeps the floor installable without forcing a toolchain
# upgrade first.
if (!eval { ExtUtils::MakeMaker->VERSION('6.64'); 1 }) {
    my $test_requires = delete $args{TEST_REQUIRES};
    $args{PREREQ_PM} = { %{ $args{PREREQ_PM} }, %$test_requires };
}

WriteMakefile(%args);

use strict;
use warnings;

use Alien::ngtcp2 0.02 ();
use ExtUtils::MakeMaker;

my %backend_define = (
    openssl   => '-DNET_QUIC_CRYPTO_OPENSSL',
    gnutls    => '-DNET_QUIC_CRYPTO_GNUTLS',
    boringssl => '-DNET_QUIC_CRYPTO_BORINGSSL',
    wolfssl   => '-DNET_QUIC_CRYPTO_WOLFSSL',
    picotls   => '-DNET_QUIC_CRYPTO_PICOTLS',
);

my $backend = Alien::ngtcp2->crypto_backend;
die "Unsupported Alien::ngtcp2 crypto backend '$backend'\n"
    if !exists $backend_define{$backend};

my $cflags = join ' ', grep { defined && length }
    Alien::ngtcp2->cflags,
    Alien::ngtcp2->crypto_cflags;

sub _makemaker_libs {
    my ($flags) = @_;

    my @out;

    for my $token (split /\s+/, $flags) {
        next if !length $token;

        if ($token =~ m{\A(.+)/([^/]+)\.(a|lib)\z}i) {
            my ($dir, $name) = ($1, $2);

            $name =~ s/\Alib//;

            push @out, "-L$dir", "-l$name";
            next;
        }

        push @out, $token;
    }

    return join ' ', @out;
}

my $libs = _makemaker_libs(
    join ' ', grep { defined && length }
        Alien::ngtcp2->libs,
        Alien::ngtcp2->crypto_libs,
);

WriteMakefile(
    NAME             => 'Net::QUIC',
    VERSION_FROM     => 'lib/Net/QUIC.pm',
    ABSTRACT_FROM    => 'lib/Net/QUIC.pm',
    AUTHOR           => 'Joshua S. Day <haxmeister@hotmail.com>',
    LICENSE          => 'mit',
    MIN_PERL_VERSION => '5.020',

    CONFIGURE_REQUIRES => {
        'Alien::ngtcp2'       => '0.02',
        'ExtUtils::MakeMaker' => 0,
    },

    PREREQ_PM => {
        'Alien::ngtcp2' => '0.02',
        'Carp'          => 0,
        'XSLoader'      => 0,
    },

    TEST_REQUIRES => {
        'Test2::V0' => 0,
    },

    INC    => $cflags,
    LIBS   => [$libs],
    DEFINE => $backend_define{$backend},

    META_MERGE => {
        'meta-spec' => {
            version => 2,
        },
        provides => {
            'Net::QUIC' => {
                file    => 'lib/Net/QUIC.pm',
                version => MM->parse_version('lib/Net/QUIC.pm'),
            },
            'Net::QUIC::Datagram' => {
                file    => 'lib/Net/QUIC/Datagram.pm',
                version => MM->parse_version('lib/Net/QUIC/Datagram.pm'),
            },
            'Net::QUIC::Endpoint' => {
                file    => 'lib/Net/QUIC/Endpoint.pm',
                version => MM->parse_version('lib/Net/QUIC/Endpoint.pm'),
            },
        },
        resources => {
            homepage => 'https://github.com/haxmeister/perl-Net-QUIC',
            repository => {
                type => 'git',
                url  => 'https://github.com/haxmeister/perl-Net-QUIC.git',
                web  => 'https://github.com/haxmeister/perl-Net-QUIC',
            },
            bugtracker => {
                web => 'https://github.com/haxmeister/perl-Net-QUIC/issues',
            },
        },
    },
);

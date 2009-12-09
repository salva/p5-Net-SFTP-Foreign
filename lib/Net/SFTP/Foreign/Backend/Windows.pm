package Net::SFTP::Foreign::Backend::Windows;

our $VERSION = '0.01';

use strict;
use warnings;

use Carp;
our @CARP_NOT = qw(Net::SFTP::Foreign);

use Net::SFTP::Foreign::Helpers;
use Net::SFTP::Foreign::Constants qw(SSH2_FX_BAD_MESSAGE
				     SFTP_ERR_REMOTE_BAD_MESSAGE);

require Net::SFTP::Foreign::Backend::Unix;
our @ISA = qw(Net::SFTP::Foreign::Backend::Unix);

sub _defaults {
    ( default_queue_size => 4 )
}

sub _init_transport_streams {
    my ($self, $sftp) = @_;
    binmode $sftp->{ssh_in};
    binmode $sftp->{ssh_out};
}

sub _sysreadn {
    my ($sftp, $n) = @_;
    my $bin = \$sftp->{_bin};
    while (1) {
	my $len = length $$bin;
	return 1 if $len >= $n;
	my $read = sysread($sftp->{ssh_in}, $$bin, $n - $len, $len);
	unless ($read) {
	    $sftp->_conn_lost;
	    return undef;
	}
    }
    return $n;
}

sub _do_io {
    my ($self, $sftp, $timeout) = @_;

    return undef unless $sftp->{_connected};

    my $bin = \$sftp->{_bin};
    my $bout = \$sftp->{_bout};

    while (length $$bout) {
	my $written = syswrite($sftp->{ssh_out}, $$bout, 20480);
	unless ($written) {
	    $sftp->_conn_lost;
	    return undef;
	}
	substr($$bout, 0, $written, "");
    }

    _sysreadn($sftp, 4) or return undef;

    my $len = 4 + unpack N => $$bin;
    if ($len > 256 * 1024) {
	$sftp->_set_status(SSH2_FX_BAD_MESSAGE);
	$sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
			  "bad remote message received");
	return undef;
    }
    _sysreadn($sftp, $len);
}

1;

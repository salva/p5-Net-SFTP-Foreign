package Net::SFTP::Foreign::Backend::Windows;

our $VERSION = '1.63_05';

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
    my ($backend, $sftp) = @_;
    binmode $sftp->{ssh_in};
    binmode $sftp->{ssh_out};
}

sub _open_dev_null {
    my $sftp = shift;
    my $dev_null;
    unless (open $dev_null, '>', 'NUL:') {
	$sftp->_conn_failed("Unable to redirect stderr for slave SSH process to NUL: $!");
	return;
    }
    $dev_null
}

# workaround for IPC::Open3 not working with tied filehandles even
# when they implement FILENO
sub _open3 {
    my $backend = shift;
    my $sftp = shift;
    if (tied(*STDERR)) {
	my $fn = eval { defined $_[2] ? fileno $_[2] : fileno *STDERR };
	unless (defined $fn and $fn >= 0) {
	    $sftp->_conn_failed("STDERR or stderr_fh is not a real file handle: " . (length $@ ? $@ : $!));
	    return;
	}
	local *STDERR;
	unless (open STDERR, ">&=$fn") {
	    $sftp->_conn_failed("Unable to reattach STDERR to fd $fn: $!");
	    return;
	}
	$backend->SUPER::_open3($sftp, @_);
    }
    else {
	$backend->SUPER::_open3($sftp, @_);
    }
}

sub _after_init {}

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
    my ($backend, $sftp, $timeout) = @_;

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

    defined $timeout and $timeout <= 0 and return;

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

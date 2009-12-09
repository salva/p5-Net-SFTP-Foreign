package Net::SFTP::Foreign::Backend::Unix;

our $VERSION = '0.01';

use strict;
use warnings;

use Fcntl qw(O_NONBLOCK F_SETFL F_GETFL);
use Net::SFTP::Foreign::Helpers;
use Net::SFTP::Foreign::Constants qw(SSH2_FX_BAD_MESSAGE
				     SFTP_ERR_REMOTE_BAD_MESSAGE);

sub new { shift }

sub use_private_transport { undef }

sub init_transport {
    my ($self, $sftp) = @_;
    for my $dir (qw(ssh_in ssh_out)) {
	binmode $sftp->{$dir};
	my $flags = fcntl($sftp->{$dir}, F_GETFL, 0);
	fcntl($sftp->{$dir}, F_SETFL, $flags | O_NONBLOCK);
    }
}

sub do_io {
    my ($self, $sftp, $timeout) = @_;

    $debug and $debug & 32 and _debug(sprintf "_do_io connected: %s", $sftp->{_connected} || 0);

    return undef unless $sftp->{_connected};

    my $fnoout = fileno $sftp->{ssh_out};
    my $fnoin = fileno $sftp->{ssh_in};
    my ($rv, $wv) = ('', '');
    vec($rv, $fnoin, 1) = 1;
    vec($wv, $fnoout, 1) = 1;

    my $bin = \$sftp->{_bin};
    my $bout = \$sftp->{_bout};

    local $SIG{PIPE} = 'IGNORE';

    my $len;
    while (1) {
        my $lbin = length $$bin;
	if (defined $len) {
            return 1 if $lbin >= $len;
	}
	elsif ($lbin >= 4) {
            $len = 4 + unpack N => $$bin;
            if ($len > 256 * 1024) {
                $sftp->_set_status(SSH2_FX_BAD_MESSAGE);
                $sftp->_set_error(SFTP_ERR_REMOTE_BAD_MESSAGE,
                                  "bad remote message received");
                return undef;
            }
            return 1 if $lbin >= $len;
        }

        my $rv1 = $rv;
        my $wv1 = length($$bout) ? $wv : '';

        $debug and $debug & 32 and _debug("_do_io select(-,-,-, ". (defined $timeout ? $timeout : 'undef') .")");

        my $n = select($rv1, $wv1, undef, $timeout);
        if ($n > 0) {
            if (vec($wv1, $fnoout, 1)) {
                my $written = syswrite($sftp->{ssh_out}, $$bout, 64 * 1024);
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io write queue: %d, syswrite: %s, max: %d",
			    length $$bout,
			    (defined $written ? $written : 'undef'),
			    64 * 1024);
		    $debug & 2048 and $written and _hexdump(substr($$bout, 0, $written));
		}
                unless ($written) {
                    $sftp->_conn_lost;
                    return undef;
                }
                substr($$bout, 0, $written, '');
            }
            if (vec($rv1, $fnoin, 1)) {
                my $read = sysread($sftp->{ssh_in}, $$bin, 64 * 1024, length($$bin));
                if ($debug and $debug & 32) {
		    _debug (sprintf "_do_io read sysread: %s, total read: %d",
			    (defined $read ? $read : 'undef'),
			    length $$bin);
		    $debug & 1024 and $read and _hexdump(substr($$bin, -$read));
		}
                unless ($read) {
                    $sftp->_conn_lost;
                    return undef;
                }
            }
        }
        else {
            $debug and $debug & 32 and _debug "_do_io select failed: $!";
            next if ($n < 0 and $! == Errno::EINTR());
            return undef;
        }
    }
}

1;

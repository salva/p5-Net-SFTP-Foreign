use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub _fill_read_cache {
    my ($sftp, $rfh, $len) = @_;

    $sftp->flush($rfh, 'out') or return undef;

    my $rid = $sftp->_rid($rfh);
    defined $rid or return undef;

    my $bin = $rfh->_bin;

    if (defined $len) {
	return 1 if ($len < length $$bin);

	my $read_ahead = $sftp->{_read_ahead};
	$len = length($$bin) + $read_ahead
	    if $len - length($$bin) < $read_ahead;
    }

    my $pos = $rfh->_pos;

    my $qsize = $sftp->{_queue_size};
    my $bsize = $sftp->{_block_size};

    my @msgid;
    my $askoff = length $$bin;
    my $eof;

    while (!defined $len or length $$bin < $len) {
	while ((!defined $len or $askoff < $len) and @msgid < $qsize) {
	    my $id = $sftp->_queue_msg(SSH2_FXP_READ, str=> $rid,
                                       uint64 => $pos + $askoff, uint32 => $bsize);
	    push @msgid, $id;
	    $askoff += $bsize;
	}

	my $eid = shift @msgid;
	my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $eid,
					    SFTP_ERR_REMOTE_READ_FAILED,
					    "Couldn't read from remote file")
	    or last;

	my $data = _buf_shift_str($msg);
	$$bin .= $data;
	if (length $data < $bsize) {
	    unless (defined $len) {
		$eof = $sftp->_queue_msg(SSH2_FXP_READ, str=> $rid,
                                         uint64 => $pos + length $$bin, uint32 => 1);
	    }
	    last;
	}

    }

    $sftp->_get_msg for @msgid;

    if ($eof) {
	$sftp->_get_msg_and_check(SSH2_FXP_DATA, $eof,
				  SFTP_ERR_REMOTE_BLOCK_TOO_SMALL,
				  "received block was too small")
    }

    if ($sftp->{_status} == SSH2_FX_EOF and length $$bin) {
	$sftp->_clear_error_and_status;
    }

    return $sftp->{_error} ? undef : length $$bin;
}

1;

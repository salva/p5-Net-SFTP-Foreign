use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub readdir {
    @_ == 2 or croak 'Usage: $sftp->readdir($dh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $rdh) = @_;

    my $rid = $sftp->_rid($rdh);
    defined $rid or return undef;

    my $cache = $rdh->_cache;

    while (!@$cache or wantarray) {
	my $id = $sftp->_queue_msg(SSH2_FXP_READDIR, str => $rid);
	if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
                                                        SFTP_ERR_REMOTE_READDIR_FAILED,
                                                        "Couldn't read remote directory"))) {
	    my $count = _buf_shift_uint32($msg) or last;

	    for (1..$count) {
                my $filename = $sftp->_buf_shift_path($msg);
                my $longname = $sftp->_buf_shift_path($msg);
                my $a = $sftp->_buf_shift_attrs($msg);

                $sftp->{_error} and last;

                push @$cache, { filename => $filename,
                                longname => $longname,
				a => $a };
	    }
	}
	else {
	    $sftp->_set_error if $sftp->{_status} == SSH2_FX_EOF;
	    last;
	}
    }

    if (wantarray) {
	my @old = @$cache;
	@$cache = ();
	return @old;
    }
    shift @$cache;
}

1;

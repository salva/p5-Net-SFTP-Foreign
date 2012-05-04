use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub setcwd {
    @_ <= 2 or croak 'Usage: $sftp->setcwd($path)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $cwd) = @_;
    $sftp->_clear_error_and_status;

    if (defined $cwd) {
        $cwd = $sftp->realpath($cwd);
        return undef unless defined $cwd;
	my $a = $sftp->stat($cwd)
	    or return undef;
	if (_is_dir($a->perm)) {
	    return $sftp->{cwd} = $cwd;
	}
	else {
	    $sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
			      "Remote object '$cwd' is not a directory");
	    return undef;
	}
    }
    else {
        delete $sftp->{cwd};
        return $sftp->cwd if defined wantarray;
    }
}

1;

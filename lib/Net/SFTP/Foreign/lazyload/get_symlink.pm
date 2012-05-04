use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub get_symlink {
    @_ >= 3 or croak 'Usage: $sftp->get_symlink($remote, $local, %opts)';
    my ($sftp, $remote, $local, %opts) = @_;
    my $overwrite = delete $opts{overwrite};
    my $numbered = delete $opts{numbered};

    croak "'overwrite' and 'numbered' can not be used together"
	if ($overwrite and $numbered);
   %opts and _croak_bad_options(keys %opts);

    $overwrite = 1 unless (defined $overwrite or $numbered);

    my $a = $sftp->lstat($remote) or return undef;
    unless (_is_lnk($a->perm)) {
	$sftp->_set_error(SFTP_ERR_REMOTE_BAD_OBJECT,
			  "Remote object '$remote' is not a symlink");
	return undef;
    }

    my $link = $sftp->readlink($remote) or return undef;

    # TODO: this is too weak, may contain race conditions.
    if ($numbered) {
        _inc_numbered($local) while -e $local;
    }
    elsif (-e $local) {
	if ($overwrite) {
	    unlink $local;
	}
	else {
	    $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
			      "local file $local already exists");
	    return undef
	}
    }

    unless (eval { CORE::symlink $link, $local }) {
	$sftp->_set_error(SFTP_ERR_LOCAL_SYMLINK_FAILED,
			  "creation of symlink '$local' failed", $!);
	return undef;
    }
    $$numbered = $local if ref $numbered;

    1;
}

1;

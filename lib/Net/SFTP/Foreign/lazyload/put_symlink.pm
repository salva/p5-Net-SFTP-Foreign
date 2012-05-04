use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub put_symlink {
    @_ >= 3 or croak 'Usage: $sftp->put_symlink($local, $remote, %opts)';
    my ($sftp, $local, $remote, %opts) = @_;
    my $overwrite = delete $opts{overwrite};
    my $numbered = delete $opts{numbered};

    croak "'overwrite' and 'numbered' can not be used together"
	if ($overwrite and $numbered);
    %opts and _croak_bad_options(keys %opts);

    $overwrite = 1 unless (defined $overwrite or $numbered);
    my $perm = (CORE::lstat $local)[2];
    unless (defined $perm) {
	$sftp->_set_error(SFTP_ERR_LOCAL_STAT_FAILED,
			  "Couldn't stat local file '$local'", $!);
	return undef;
    }
    unless (_is_lnk($perm)) {
	$sftp->_set_error(SFTP_ERR_LOCAL_BAD_OBJECT,
			  "Local file $local is not a symlink");
	return undef;
    }
    my $target = readlink $local;
    unless (defined $target) {
	$sftp->_set_error(SFTP_ERR_LOCAL_READLINK_FAILED,
			  "Couldn't read link '$local'", $!);
	return undef;
    }

    while (1) {
        local $sftp->{_autodie};
        $sftp->symlink($remote, $target);
        if ($sftp->{_error} and
            $sftp->{_status} == SSH2_FX_FAILURE) {
            if ($numbered and $sftp->test_e($remote)) {
                _inc_numbered($remote);
                redo;
            }
            elsif ($overwrite and $sftp->_with_save_error(remove => $remote)) {
                $overwrite = 0;
                redo;
            }
        }
        last
    }
    $$numbered = $remote if ref $numbered;
    $sftp->_ok_or_autodie;
}

1;

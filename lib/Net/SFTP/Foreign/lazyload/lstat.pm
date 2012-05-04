use strict;
use warnings;
no warnings 'redefine';

sub lstat {
    @_ == 2 or croak 'Usage: $sftp->lstat($path)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path) = @_;
    my $id = $sftp->_queue_msg(SSH2_FXP_LSTAT, abs_path => $path);
    if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_ATTRS, $id,
                                                    SFTP_ERR_REMOTE_LSTAT_FAILED,
                                                    "Couldn't stat remote link"))) {
        return $sftp->_buf_shift_attrs($msg);
    }
    return undef;
}

1;

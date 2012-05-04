use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub stat {
    @_ == 2 or croak 'Usage: $sftp->stat($path_or_fh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $pofh) = @_;
    my $id = $sftp->_queue_pofh_msg(SSH2_FXP_STAT, SSH2_FXP_FSTAT, $pofh);
    if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_ATTRS, $id,
                                                    SFTP_ERR_REMOTE_STAT_FAILED,
                                                    "Couldn't stat remote file"))) {
        return $sftp->_buf_shift_attrs($msg);
    }
    return undef;
}

1;

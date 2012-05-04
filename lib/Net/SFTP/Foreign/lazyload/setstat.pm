use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub setstat {
    @_ == 3 or croak 'Usage: $sftp->setstat($path_or_fh, $attrs)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $pofh, $attrs) = @_;
    my $id = $sftp->_queue_pofh_msg(SSH2_FXP_SETSTAT, SSH2_FXP_FSETSTAT, $pofh, attrs => $attrs);
    $sftp->_get_status_msg_and_check($id,
                                     SFTP_ERR_REMOTE_SETSTAT_FAILED,
                                     "Couldn't setstat remote file'");
}

1;

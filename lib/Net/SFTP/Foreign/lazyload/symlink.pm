use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub symlink {
    @_ == 3 or croak 'Usage: $sftp->symlink($sl, $target)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $sl, $target) = @_;
    my $id = $sftp->_queue_msg(SSH2_FXP_SYMLINK,
                               path => $target,
                               abs_path => $sl);
    $sftp->_get_status_msg_and_check($id, SFTP_ERR_REMOTE_SYMLINK_FAILED,
                                     "Couldn't create symlink '$sl' pointing to '$target'");
}

1;

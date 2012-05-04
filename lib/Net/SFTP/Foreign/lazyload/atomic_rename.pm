use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub atomic_rename {
    @_ == 3 or croak 'Usage: $sftp->atomic_rename($old, $new)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $old, $new) = @_;

    my $id = $sftp->_queue_extended_msg('posix-rename@openssh.com' => 1,
                                        SFTP_ERR_REMOTE_RENAME_FAILED,
                                        "atomic rename failed",
                                        abs_path => $old,
                                        abs_path => $new);

    $sftp->_get_status_msg_and_check($id, SFTP_ERR_REMOTE_RENAME_FAILED,
                                     "Couldn't rename remote file '$old' to '$new'");
}

1;

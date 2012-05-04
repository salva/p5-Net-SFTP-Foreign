use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub hardlink {
    @_ == 3 or croak 'Usage: $sftp->hardlink($hl, $target)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $hl, $target) = @_;

    my $id = $sftp->_queue_extended_msg('hardlink@openssh.com' => 1,
                                        SFTP_ERR_REMOTE_HARDLINK_FAILED,
                                        "hardlink failed",
                                        abs_path => $target,
                                        abs_path => $hl);
    $sftp->_get_status_msg_and_check($id, SFTP_ERR_REMOTE_HARDLINK_FAILED,
                                     "Couldn't create hardlink '$hl' pointing to '$target'");
}

1;

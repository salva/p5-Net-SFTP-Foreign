use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub mkdir {
    (@_ >= 2 and @_ <= 3)
        or croak 'Usage: $sftp->mkdir($path [, $attrs])';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $path, $attrs) = @_;
    my $id = $sftp->_queue_msg(SSH2_FXP_MKDIR,
                               abs_path => $path, attrs => $attrs);
    $sftp->_get_status_msg_and_check($id,
                                     SFTP_ERR_REMOTE_MKDIR_FAILED,
                                     "Couldn't create remote directory");
}

1;

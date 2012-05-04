use strict;
use warnings;
no warnings 'redefine';

sub sftpwrite {
    @_ == 4 or croak 'Usage: $sftp->sftpwrite($fh, $offset, $data)';

    my ($sftp, $rfh, $offset) = @_;
    utf8::downgrade($_[3], 1) or croak "wide characters found in data";

    my $id = $sftp->_queue_msg(SSH2_FXP_WRITE, fh => $rfh,
                               uint64 => $offset, str => $_[3]);

    if ($sftp->_get_status_msg_and_check($id,
                                         SFTP_ERR_REMOTE_WRITE_FAILED,
                                         "Couldn't write to remote file")) {
	return 1;
    }
    return undef;
}

1;

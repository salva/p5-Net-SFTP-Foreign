use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub sftpread {
    (@_ >= 3 and @_ <= 4)
	or croak 'Usage: $sftp->sftpread($fh, $offset [, $size])';

    my ($sftp, $rfh, $offset, $size) = @_;

    unless ($size) {
	return '' if defined $size;
	$size = $sftp->{_block_size};
    }

    my $id = $sftp->_queue_msg(SSH2_FXP_READ, fh => $rfh,
                               uint64 => $offset, uint32 => $size);

    if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $id,
                                                    SFTP_ERR_REMOTE_READ_FAILED,
                                                    "Couldn't read from remote file"))) {
	return _buf_shift_str($msg);
    }
    return undef;
}

1;

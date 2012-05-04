use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub statvfs {
    @_ == 2 or croak 'Usage: $sftp->statvfs($path_or_fh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $pofh) = @_;
    my ($extension, $packer) = (_is_fh($pofh)
                                ? ('fstatvfs@openssh.com', 'fh')
                                : ('statvfs@openssh.com' , 'abs_path'));

    $sftp->_check_extension($extension => 2,
                            SFTP_ERR_REMOTE_STATVFS_FAILED,
                            "statvfs failed")
        or return undef;

    my $id = $sftp->_queue_new_msg(SSH2_FXP_EXTENDED,
                                   str => $extension,
                                   $packer => $pofh);

    if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_EXTENDED_REPLY, $id,
                                                    SFTP_ERR_REMOTE_STATVFS_FAILED,
                                                    "Couldn't stat remote file system"))) {
        my %statvfs = map { $_ => $msg->get_int64 } qw(bsize frsize blocks
                                                       bfree bavail files ffree
                                                       favail fsid flag namemax);
        return \%statvfs;
    }
    return undef;
}

1;

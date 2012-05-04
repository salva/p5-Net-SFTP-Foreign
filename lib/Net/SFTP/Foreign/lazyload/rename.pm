use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub _rename {
    my ($sftp, $old, $new) = @_;
    my $id = $sftp->_queue_msg(SSH2_FXP_RENAME,
                               abs_path => $old,
                               abs_path => $new);

    $sftp->_get_status_msg_and_check($id, SFTP_ERR_REMOTE_RENAME_FAILED,
                                     "Couldn't rename remote file '$old' to '$new'");
}

sub rename {
    (@_ & 1) or croak 'Usage: $sftp->rename($old, $new, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $old, $new, %opts) = @_;

    my $overwrite = delete $opts{overwrite};
    my $numbered = delete $opts{numbered};
    croak "'overwrite' and 'numbered' options can not be used together"
        if ($overwrite and $numbered);
    %opts and _croak_bad_options(keys %opts);

    if ($overwrite) {
        $sftp->atomic_rename($old, $new) and return 1;
        $sftp->{_status} != SSH2_FX_OP_UNSUPPORTED and return undef;
    }

    for (1) {
        local $sftp->{_autodie};
        # we are optimistic here and try to rename it without testing
        # if a file of the same name already exists first
        if (!$sftp->_rename($old, $new) and
            $sftp->{_status} == SSH2_FX_FAILURE) {
            if ($numbered and $sftp->test_e($new)) {
                _inc_numbered($new);
                redo;
            }
            elsif ($overwrite) {
                my $rp_old = $sftp->realpath($old);
                my $rp_new = $sftp->realpath($new);
                if (defined $rp_old and defined $rp_new and $rp_old eq $rp_new) {
                    $sftp->_clear_error;
                }
                elsif ($sftp->remove($new)) {
                    $overwrite = 0;
                    redo;
                }
            }
        }
    }
    $sftp->_ok_or_autodie;
}

1;

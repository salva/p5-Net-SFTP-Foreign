use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub put_content {
    @_ >= 3 or croak 'Usage: $sftp->put_content($content, $remote, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, undef, $remote, %opts) = @_;
    my %put_opts = ( map { $_ => delete $opts{$_} }
                     qw(perm umask block_size queue_size overwrite conversion resume
                        numbered late_set_perm atomic best_effort));
    %opts and _croak_bad_options(keys %opts);

    my $fh;
    unless (CORE::open $fh, '<', \$_[0]) {
        $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED, "Can't open scalar as file handle", $!);
        return undef;
    }
    $sftp->put($fh, $remote, %opts);

}

1;

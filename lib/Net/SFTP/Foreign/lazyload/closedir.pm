use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub closedir {
    @_ == 2 or croak 'Usage: $sftp->closedir($dh)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $rdh) = @_;
    $rdh->_check_is_dir;

    $sftp->_close($rdh) and $rdh->_close;
    return !$sftp->{_error};
}

1;

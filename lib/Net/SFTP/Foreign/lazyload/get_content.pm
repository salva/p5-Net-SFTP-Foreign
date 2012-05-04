use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub get_content {
    @_ == 2 or croak 'Usage: $sftp->get_content($remote)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $name) = @_;
    my $rfh = $sftp->open($name)
	or return undef;

    scalar $sftp->readline($rfh, undef);
}

1;

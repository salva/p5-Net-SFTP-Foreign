use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub getc {
    @_ == 2 or croak 'Usage: $sftp->getc($fh)';

    my ($sftp, $rfh) = @_;

    $sftp->_fill_read_cache($rfh, 1);
    my $bin = $rfh->_bin;
    if (length $bin) {
	$rfh->_inc_pos(1);
	return substr $$bin, 0, 1, '';
    }
    return undef;
}

1;

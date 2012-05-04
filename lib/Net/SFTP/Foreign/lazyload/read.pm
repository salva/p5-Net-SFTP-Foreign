use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub read {
    @_ == 3 or croak 'Usage: $sftp->read($fh, $len)';

    my ($sftp, $rfh, $len) = @_;
    if ($sftp->_fill_read_cache($rfh, $len)) {
	my $bin = $rfh->_bin;
	my $data = substr($$bin, 0, $len, '');
	$rfh->_inc_pos(length $data);
	return $data;
    }
    return undef;
}

1;

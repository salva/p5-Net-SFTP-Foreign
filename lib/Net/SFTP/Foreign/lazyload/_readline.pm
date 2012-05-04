use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub _readline {
    my ($sftp, $rfh, $sep) = @_;

    $sep = "\n" if @_ < 3;

    my $sl = length $sep;

    my $bin = $rfh->_bin;
    my $last = 0;

    while(1) {
	my $ix = index $$bin, $sep, $last + 1 - $sl ;
	if ($ix >= 0) {
	    $ix += $sl;
	    $rfh->_inc_pos($ix);
	    return substr($$bin, 0, $ix, '');
	}

	$last = length $$bin;
	$sftp->_fill_read_cache($rfh, length($$bin) + 1);

	unless (length $$bin > $last) {
	    $sftp->{_error}
		and return undef;

	    my $line = $$bin;
	    $rfh->_inc_pos(length $line);
	    $$bin = '';
	    return $line;
	}
    }
}

1;

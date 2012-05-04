use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub readline {
    (@_ >= 2 and @_ <= 3)
	or croak 'Usage: $sftp->readline($fh [, $sep])';

    my ($sftp, $rfh, $sep) = @_;
    $sep = "\n" if @_ < 3;
    if (!defined $sep or $sep eq '') {
	$sftp->_fill_read_cache($rfh);
	$sftp->{_error}
	    and return undef;
	my $bin = $rfh->_bin;
	my $line = $$bin;
	$rfh->_inc_pos(length $line);
	$$bin = '';
	return $line;
    }
    if (wantarray) {
	my @lines;
	while (defined (my $line = $sftp->_readline($rfh, $sep))) {
	    push @lines, $line;
	}
	return @lines;
    }
    return $sftp->_readline($rfh, $sep);
}

1;

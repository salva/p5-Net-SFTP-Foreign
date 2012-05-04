use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub seek {
    (@_ >= 3 and @_ <= 4)
	or croak 'Usage: $sftp->seek($fh, $pos [, $whence])';

    my ($sftp, $rfh, $pos, $whence) = @_;
    $sftp->flush($rfh) or return undef;

    $whence ||= 0;

    if ($whence == 0) {
	return $rfh->_pos($pos)
    }
    elsif ($whence == 1) {
	return $rfh->_inc_pos($pos)
    }
    elsif ($whence == 2) {
	if (my $a = $sftp->stat($rfh)) {
	    return $rfh->_pos($pos + $a->size);
	}
	else {
	    return undef;
	}
    }
    else {
	croak "invalid whence argument";
    }
}

1;

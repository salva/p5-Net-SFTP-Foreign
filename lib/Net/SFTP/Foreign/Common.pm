package Net::SFTP::Foreign::Common;

our $VERSION = '1.48';

use strict;
use warnings;
use Carp;
use Scalar::Util qw(dualvar tainted);
use Fcntl qw(S_ISLNK S_ISDIR);

use Net::SFTP::Foreign::Helpers qw(_gen_wanted _ensure_list _debug $debug);
use Net::SFTP::Foreign::Constants qw(:status);

my %status_str = ( SSH2_FX_OK, "OK",
		   SSH2_FX_EOF, "End of file",
		   SSH2_FX_NO_SUCH_FILE, "No such file or directory",
		   SSH2_FX_PERMISSION_DENIED, "Permission denied",
		   SSH2_FX_FAILURE, "Failure",
		   SSH2_FX_BAD_MESSAGE, "Bad message",
		   SSH2_FX_NO_CONNECTION, "No connection",
		   SSH2_FX_CONNECTION_LOST, "Connection lost",
		   SSH2_FX_OP_UNSUPPORTED, "Operation unsupported" );

our $debug;

sub _set_status {
    my $sftp = shift;
    my $code = shift;
    if ($code) {
        my $str;
        if (@_) {
            $str = join ': ', @_;
            ($str) = $str =~ /(.*)/
                if (${^TAINT} && tainted $str);
        }
        unless (defined $str and length $str) {
            $str = $status_str{$code} || "Unknown status ($code)";
        }
        $debug and $debug & 64 and _debug("_set_status code: $code, str: $str");
	return $sftp->{_status} = dualvar($code, $str);
    }
    else {
	return $sftp->{_status} = 0;
    }
}

sub status { shift->{_status} }

sub _set_error {
    my $sftp = shift;
    my $code = shift;
    if ($code) {
        my $str;
        if (@_) {
            $str = join ': ', @_;
            ($str) = $str =~ /(.*)/
                if (${^TAINT} && tainted $str);
        }
        else {
	    $str = $code ? "Unknown error $code" : "OK";
	}
        $debug and $debug & 64 and _debug("_set_err code: $code, str: $str");
	return $sftp->{_error} = dualvar $code, $str;
    }
    else {
	return $sftp->{_error} = 0;
    }
}

sub _clear_error_and_status {
    my $sftp = shift;
    $sftp->{_error} = 0;
    $sftp->{_status} = 0;
}

sub _copy_error {
    $_[0]->{_error} = $_[1]->{_error};
}

sub error { shift->{_error} }

sub _set_errno {
    my $sftp = shift;
    if ($sftp->{_error}) {
	my $status = $sftp->{_status} + 0;
	my $error = $sftp->{_error} + 0;
	if ($status == SSH2_FX_EOF) {
	    return;
	}
        elsif ($status == SSH2_FX_NO_SUCH_FILE) {
	    $! = Errno::ENOENT();
	}
	elsif ($status == SSH2_FX_PERMISSION_DENIED) {
	    $! = Errno::EACCES();
	}
	elsif ($status == SSH2_FX_BAD_MESSAGE) {
	    $! = Errno::EBADMSG();
	}
	elsif ($status == SSH2_FX_OP_UNSUPPORTED) {
	    $! = Errno::ENOTSUP()
	}
	elsif ($status) {
	    $! = Errno::EIO()
	}
    }
}

sub _call_on_error {
    my ($sftp, $on_error, $entry) = @_;
    if ($on_error and $sftp->error) {
	$on_error->($sftp, $entry);
	$sftp->_set_error;
	$sftp->_set_status;
    }
}

# this method code is a little convoluted because we are trying to
# keep in memory as few entries as possible!!!
sub find {
    @_ >= 1 or croak 'Usage: $sftp->find($remote_dirs, %opts)';

    my $self = shift;
    my %opts = @_ & 1 ? ('dirs', @_) : @_;

    $self->_set_error;
    $self->_set_status;

    my $dirs = delete $opts{dirs};
    my $follow_links = delete $opts{follow_links};
    my $on_error = delete $opts{on_error};
    my $realpath = delete $opts{realpath};
    my $ordered = delete $opts{ordered};
    my $names_only = delete $opts{names_only};
    my $atomic_readdir = delete $opts{atomic_readdir};
    my $wanted = _gen_wanted( delete $opts{wanted},
			      delete $opts{no_wanted} );
    my $descend = _gen_wanted( delete $opts{descend},
			       delete $opts{no_descend} );

    %opts and croak "invalid option(s) '".CORE::join("', '", keys %opts)."'";

    $dirs = '.' unless defined $dirs;

    my $wantarray = wantarray;
    my (@res, $res);
    my %done;
    my %rpdone; # used to detect cycles

    my @dirs = _ensure_list $dirs;
    my @queue = map { { filename => $_ } } ($ordered ? sort @dirs : @dirs);

    # we use a clousure instead of an auxiliary method to have access
    # to the state:

    my $task = sub {
	my $entry = shift;
	my $fn = $entry->{filename};
	for (1) {
	    my $follow = ($follow_links and S_ISLNK($entry->{a}->perm));

	    if ($follow or $realpath) {
		unless (defined $entry->{realpath}) {
                    my $rp = $self->{realpath} = $self->realpath($fn);
                    next unless (defined $rp and not $rpdone{$rp}++);
		}
	    }

	    if ($follow) {
                my $a = $self->stat($fn);
                if (defined $a) {
                    $entry->{a} = $a;
                    # we queue it for reprocessing as it could be a directory
                    unshift @queue, $entry;
                }
		next;
	    }

	    if (!$wanted or $wanted->($self, $entry)) {
		if ($wantarray) {
                    push @res, ( $names_only
                                 ? ( exists $entry->{realpath}
                                     ? $entry->{realpath}
                                     : $entry->{filename} )
                                 : $entry )
		}
		else {
		    $res++;
		}
	    }
	}
	continue {
	    $self->_call_on_error($on_error, $entry)
	}
    };

    my $try;
    while (@queue) {
	no warnings 'uninitialized';
	$try = shift @queue;
	my $fn = $try->{filename};

	my $a = $try->{a} ||= $self->lstat($fn)
	    or next;

	next if (S_ISDIR($a->perm) and $done{$fn}++);

	$task->($try);

	if (S_ISDIR($a->perm)) {
	    if (!$descend or $descend->($self, $try)) {
		if ($ordered or $atomic_readdir) {
		    my $ls = $self->ls( $fn,
					ordered => $ordered,
					_wanted => sub {
					    my $child = $_[1]->{filename};
					    if ($child !~ /^\.\.?$/) {
						$_[1]->{filename} = $self->join($fn, $child);
						return 1;
					    }
					    undef;
					})
			or next;
		    unshift @queue, @$ls;
		}
		else {
		    $self->ls( $fn,
			       _wanted => sub {
				   my $entry = $_[1];
				   my $child = $entry->{filename};
				   if ($child !~ /^\.\.?$/) {
				       $entry->{filename} = $self->join($fn, $child);

				       if (S_ISDIR($entry->{a}->perm)) {
					   push @queue, $entry;
				       }
				       else {
					   $task->($entry);
				       }
				   }
				   undef } )
			or next;
		}
	    }
	}
    }
    continue {
	$self->_call_on_error($on_error, $try)
    }

    return wantarray ? @res : $res;
}

sub test_d {
    my ($sftp, $name) = @_;
    my $a = $sftp->stat($name);
    $a ? S_ISDIR($a->perm) : undef;
}

1;


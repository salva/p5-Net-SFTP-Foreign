use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub ls {
    @_ >= 1 or croak 'Usage: $sftp->ls($remote_dir, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my $sftp = shift;
    my %opts = @_ & 1 ? (dir => @_) : @_;

    my $dir = delete $opts{dir};
    my $ordered = delete $opts{ordered};
    my $follow_links = delete $opts{follow_links};
    my $atomic_readdir = delete $opts{atomic_readdir};
    my $names_only = delete $opts{names_only};
    my $realpath = delete $opts{realpath};
    my $queue_size = delete $opts{queue_size};
    my $cheap = ($names_only and !$realpath); 
    my ($cheap_wanted, $wanted);
    if ($cheap and
	ref $opts{wanted} eq 'RegExp' and 
	not defined $opts{no_wanted}) {
	$cheap_wanted = delete $opts{wanted}
    }
    else {
	$wanted = (delete $opts{_wanted} ||
		   _gen_wanted(delete $opts{wanted},
			       delete $opts{no_wanted}));
	undef $cheap if defined $wanted;
    }

    %opts and _croak_bad_options(keys %opts);

    my $delayed_wanted = ($atomic_readdir and $wanted);
    $queue_size = 1 if ($follow_links or $realpath or
			($wanted and not $delayed_wanted));
    my $max_queue_size = $queue_size || $sftp->{_queue_size};
    $queue_size ||= 2;

    $dir = '.' unless defined $dir;
    $dir = $sftp->_rel2abs($dir);

    my $rdh = $sftp->opendir($dir);
    return unless defined $rdh;

    my $rid = $sftp->_rid($rdh);
    defined $rid or return undef;

    my @dir;
    my @msgid;

    do {
        local $sftp->{_autodie};
    OK: while (1) {
            push @msgid, $sftp->_queue_msg(SSH2_FXP_READDIR, str => $rid)
                while (@msgid < $queue_size);

            my $id = shift @msgid;
            if (defined(my $msg = $sftp->_get_msg_and_check(SSH2_FXP_NAME, $id,
                                                            SFTP_ERR_REMOTE_READDIR_FAILED,
                                                            "Couldn't read directory '$dir'"))) {
                my $count = _buf_shift_uint32($msg) or last;

                if ($cheap) {
                    for (1..$count) {
                        my $fn = $sftp->_buf_shift_path($msg);
                        push @dir, $fn if (!defined $cheap_wanted or $fn =~ $cheap_wanted);
                        _buf_shift_str($msg);
                        $sftp->_buf_skip_attrs($msg);
                    }
                }
                else {
                    for (1..$count) {
                        my $fn = $sftp->_buf_shift_path($msg);
                        my $ln = $sftp->_buf_shift_path($msg);
                        my $a = $sftp->_buf_shift_attrs($msg);

                        my $entry =  { filename => $fn,
                                       longname => $ln,
                                       a => $a };

                        if ($follow_links and _is_lnk($a->perm)) {

                            if ($a = $sftp->stat($sftp->join($dir, $fn))) {
                                $entry->{a} = $a;
                            }
                            else {
                                $sftp->_clear_error_and_status;
                            }
                        }

                        if ($realpath) {
                            my $rp = $sftp->realpath($sftp->join($dir, $fn));
                            if (defined $rp) {
                                $fn = $entry->{realpath} = $rp;
                            }
                            else {
                                $sftp->_clear_error_and_status;
                            }
                        }

                        if (!$wanted or $delayed_wanted or $wanted->($sftp, $entry)) {
                            push @dir, (($names_only and !$delayed_wanted) ? $fn : $entry);
                        }
                    }
                }

                $queue_size ++ if $queue_size < $max_queue_size;
            }
            else {
                $sftp->_set_error if $sftp->{_status} == SSH2_FX_EOF;
                $sftp->_get_msg for @msgid;
                last;
            }
        }
        $rdh and $sftp->_with_save_error(closedir => $rdh);
    };
    unless ($sftp->{_error}) {
	if ($delayed_wanted) {
	    @dir = grep { $wanted->($sftp, $_) } @dir;
	    @dir = map { defined $_->{realpath}
			 ? $_->{realpath}
			 : $_->{filename} } @dir
		if $names_only;
	}
        if ($ordered) {
            if ($names_only) {
                @dir = sort @dir;
            }
            else {
                _sort_entries \@dir;
            }
        }
	return \@dir;
    }
    $sftp->_ok_or_autodie;
}

1;

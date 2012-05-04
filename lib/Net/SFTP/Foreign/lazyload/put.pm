
use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub put {
    @_ >= 2 or croak 'Usage: $sftp->put($local, $remote, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $local, $remote, %opts) = @_;
    defined $local or croak "local file path is undefined";

    $sftp->_clear_error_and_status;

    my $local_is_fh = (ref $local and $local->isa('GLOB'));
    unless (defined $remote) {
        $local_is_fh and croak "unable to infer remote file name when a file handler is passed as local";
        $remote = (File::Spec->splitpath($local))[2];
    }
    $remote = $sftp->_rel2abs($remote);

    my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perm = delete $opts{copy_perm};
    $copy_perm = delete $opts{copy_perms} unless defined $copy_perm;
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $resume = delete $opts{resume};
    my $append = delete $opts{append};
    my $block_size = delete $opts{block_size} || $sftp->{_block_size};
    my $queue_size = delete $opts{queue_size} || $sftp->{_queue_size};
    my $conversion = delete $opts{conversion};
    my $late_set_perm = delete $opts{late_set_perm};
    my $numbered = delete $opts{numbered};
    my $atomic = delete $opts{atomic};
    my $cleanup = delete $opts{cleanup};
    my $best_effort = delete $opts{best_effort};
    my $sparse = delete $opts{sparse};

    croak "'perm' and 'umask' options can not be used simultaneously"
	if (defined $perm and defined $umask);
    croak "'perm' and 'copy_perm' options can not be used simultaneously"
	if (defined $perm and $copy_perm);
    croak "'resume' and 'append' options can not be used simultaneously"
	if ($resume and $append);
    croak "'resume' and 'overwrite' options can not be used simultaneously"
	if ($resume and $overwrite);
    croak "'numbered' can not be used with 'overwrite', 'resume' or 'append'"
	if ($numbered and ($overwrite or $resume or $append));
    croak "'atomic' can not be used with 'resume' or 'append'"
        if ($atomic and ($resume or $append));

    %opts and _croak_bad_options(keys %opts);

    $overwrite = 1 unless (defined $overwrite or $numbered);
    $copy_perm = 1 unless (defined $perm or defined $copy_perm or $local_is_fh);
    $copy_time = 1 unless (defined $copy_time or $local_is_fh);
    $late_set_perm = $sftp->{_late_set_perm} unless defined $late_set_perm;
    $cleanup = ($atomic || $numbered) unless defined $cleanup;

    my $neg_umask;
    if (defined $perm) {
	$neg_umask = $perm;
    }
    else {
	$umask = umask unless defined $umask;
	$neg_umask = 0777 & ~$umask;
    }

    my ($fh, $lmode, $lsize, $latime, $lmtime);
    if ($local_is_fh) {
	$fh = $local;
	# we don't set binmode for the passed file handle on purpose
    }
    else {
	unless (CORE::open $fh, '<', $local) {
	    $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
			      "Unable to open local file '$local'", $!);
	    return undef;
	}
	binmode $fh;
    }

    {
	# as $fh can come from the outside, it may be a tied object
	# lacking support for some methods, so we call them wrapped
	# inside eval blocks
	local ($@, $SIG{__DIE__}, $SIG{__WARN__});
	if ((undef, undef, $lmode, undef, undef,
	     undef, undef, $lsize, $latime, $lmtime) =
	    eval {
		no warnings; # Calling stat on a tied handler
                             # generates a warning because the op is
                             # not supported by the tie API.
		CORE::stat $fh;
	    }
	   ) {
            $debug and $debug & 16384 and _debug "local file size is " . (defined $lsize ? $lsize : '<undef>');

	    # $fh can point at some place inside the file, not just at the
	    # begining
	    if ($local_is_fh and defined $lsize) {
		my $tell = eval { CORE::tell $fh };
		$lsize -= $tell if $tell and $tell > 0;
	    }
	}
	elsif ($copy_perm or $copy_time) {
	    $sftp->_set_error(SFTP_ERR_LOCAL_STAT_FAILED,
			      "Couldn't stat local file '$local'", $!);
	    return undef;
	}
	elsif ($resume and $resume eq 'auto') {
            $debug and $debug & 16384 and _debug "not resuming because stat'ing the local file failed";
	    undef $resume
	}
    }

    $perm = $lmode & $neg_umask if $copy_perm;
    my $attrs = Net::SFTP::Foreign::Attributes->new;
    $attrs->set_perm($perm) if defined $perm;

    my $rfh;
    my $writeoff = 0;
    my $converter = _gen_converter $conversion;
    my $converted_input = '';
    my $rattrs;

    if ($resume or $append) {
	$rattrs = do {
            local $sftp->{_autodie};
            $sftp->stat($remote);
        };
	if ($rattrs) {
	    if ($resume and $resume eq 'auto' and $rattrs->mtime >= $lmtime) {
                $debug and $debug & 16384 and
                    _debug "not resuming because local file is newer, r: ".$rattrs->mtime." l: $lmtime";
		undef $resume;
	    }
	    else {
		$writeoff = $rattrs->size;
		$debug and $debug & 16384 and _debug "resuming from $writeoff";
	    }
	}
        else {
            if ($append) {
                $sftp->{_status} == SSH2_FX_NO_SUCH_FILE
                    or $sftp->_ok_or_autodie or return undef;
                # no such file, no append
                undef $append;
            }
            $sftp->_clear_error_and_status;
        }
    }

    my ($atomic_numbered, $atomic_remote);
    if ($writeoff) {
        # one of $resume or $append is set
        if ($resume) {
            $debug and $debug & 16384 and _debug "resuming file transfer from $writeoff";
            if ($converter) {
                # as size could change, we have to read and convert
                # data until we reach the given position on the local
                # file:
                my $off = 0;
                my $eof_t;
                while (1) {
                    my $len = length $converted_input;
                    my $delta = $writeoff - $off;
                    if ($delta <= $len) {
                        $debug and $debug & 16384 and _debug "discarding $delta converted bytes";
                        substr $converted_input, 0, $delta, '';
                        last;
                    }
                    else {
                        $off += $len;
                        if ($eof_t) {
                            $sftp->_set_error(SFTP_ERR_REMOTE_BIGGER_THAN_LOCAL,
                                              "Couldn't resume transfer, remote file is bigger than local");
                            return undef;
                        }
                        my $read = CORE::read($fh, $converted_input, $block_size * 4);
                        unless (defined $read) {
                            $sftp->_set_error(SFTP_ERR_LOCAL_READ_ERROR,
                                              "Couldn't read from local file '$local' to the resume point $writeoff", $!);
                            return undef;
                        }
                        $lsize += $converter->($converted_input) if defined $lsize;
                        utf8::downgrade($converted_input, 1)
                                or croak "converter introduced wide characters in data";
                        $read or $eof_t = 1;
                    }
                }
            }
            elsif ($local_is_fh) {
                # as some PerlIO layer could be installed on the $fh,
                # just seeking to the resume position will not be
                # enough. We have to read and discard data until the
                # desired offset is reached
                my $off = $writeoff;
                while ($off) {
                    my $read = CORE::read($fh, my($buf), ($off < 16384 ? $off : 16384));
                    if ($read) {
                        $debug and $debug & 16384 and _debug "discarding $read bytes";
                        $off -= $read;
                    }
                    else {
                        $sftp->_set_error(defined $read
                                          ? ( SFTP_ERR_REMOTE_BIGGER_THAN_LOCAL,
                                              "Couldn't resume transfer, remote file is bigger than local")
                                          : ( SFTP_ERR_LOCAL_READ_ERROR,
                                              "Couldn't read from local file handler '$local' to the resume point $writeoff", $!));
                    }
                }
            }
            else {
                if (defined $lsize and $writeoff > $lsize) {
                    $sftp->_set_error(SFTP_ERR_REMOTE_BIGGER_THAN_LOCAL,
                                      "Couldn't resume transfer, remote file is bigger than local");
                    return undef;
                }
                unless (CORE::seek($fh, $writeoff, 0)) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_SEEK_FAILED,
                                      "seek operation on local file failed: $!");
                    return undef;
                }
            }
            if (defined $lsize and $writeoff == $lsize) {
                if (defined $perm and $rattrs->perm != $perm) {
                    # FIXME: do copy_time here if required
                    return $sftp->_with_best_effort($best_effort, setstat => $remote, $attrs);
                }
                return 1;
            }
        }
        $rfh = $sftp->open($remote, SSH2_FXF_WRITE)
            or return undef;
    }
    else {
        if ($atomic) {
            # check that does not exist a file of the same name that
            # would block the rename operation at the end
            if (!($numbered or $overwrite) and
                $sftp->test_e($remote)) {
                $sftp->_set_status(SSH2_FX_FAILURE);
                $sftp->_set_error(SFTP_ERR_REMOTE_ALREADY_EXISTS,
                                  "Remote file '$remote' already exists");
                return undef;
            }
            $atomic_remote = $remote;
            $remote .= sprintf("(%d).tmp", rand(10000));
            $atomic_numbered = $numbered;
            $numbered = 1;
            $debug and $debug & 128 and _debug("temporal remote file name: $remote");
        }
        local $sftp->{_autodie};
	if ($numbered) {
            while (1) {
                $rfh = $sftp->open($remote,
                                   SSH2_FXF_WRITE | SSH2_FXF_CREAT | SSH2_FXF_EXCL,
                                   $attrs);
                last if ($rfh or
                         $sftp->{_status} != SSH2_FX_FAILURE or
                         !$sftp->test_e($remote));
                _inc_numbered($remote);
	    }
            $$numbered = $remote if $rfh and ref $numbered;
	}
        else {
            # open can fail due to a remote file with the wrong
            # permissions being already there. We are optimistic here,
            # first we try to open the remote file and if it fails due
            # to a permissions error then we remove it and try again.
            for my $rep (0, 1) {
                $rfh = $sftp->open($remote,
                                   SSH2_FXF_WRITE | SSH2_FXF_CREAT |
                                   ($overwrite ? SSH2_FXF_TRUNC : SSH2_FXF_EXCL),
                                   $attrs);

                last if $rfh or $rep or !$overwrite or $sftp->{_status} != SSH2_FX_PERMISSION_DENIED;

                $debug and $debug & 2 and _debug("retrying open after removing remote file");
                local ($sftp->{_status}, $sftp->{_error});
                $sftp->remove($remote);
            }
        }
    }

    $sftp->_ok_or_autodie or return undef;
    # Once this point is reached and for the remaining of the sub,
    # code should never return but jump into the CLEANUP block.

    my $last_block_was_zeros;

    do {
        local $sftp->{autodie};

        # In some SFTP server implementations, open does not set the
        # attributes for existent files so we do it again. The
        # $late_set_perm work around is for some servers that do not
        # support changing the permissions of open files
        if (defined $perm and !$late_set_perm) {
            $sftp->_with_best_effort($best_effort, setstat => $rfh, $attrs) or goto CLEANUP;
        }

        my $rid = $sftp->_rid($rfh);
        defined $rid or die "internal error: rid is undef";

        # In append mode we add the size of the remote file in
        # writeoff, if lsize is undef, we initialize it to $writeoff:
        $lsize += $writeoff if ($append or not defined $lsize);

        # when a converter is used, the EOF can become delayed by the
        # buffering introduced, we use $eof_t to account for that.
        my ($eof, $eof_t);
        my @msgid;
    OK: while (1) {
            if (!$eof and @msgid < $queue_size) {
                my ($data, $len);
                if ($converter) {
                    while (!$eof_t and length $converted_input < $block_size) {
                        my $read = CORE::read($fh, my $input, $block_size * 4);
                        unless ($read) {
                            unless (defined $read) {
                                $sftp->_set_error(SFTP_ERR_LOCAL_READ_ERROR,
                                                  "Couldn't read from local file '$local'", $!);
                                last OK;
                            }
                            $eof_t = 1;
                        }

                        # note that the $converter is called a last time
                        # with an empty string
                        $lsize += $converter->($input);
                        utf8::downgrade($input, 1)
                                or croak "converter introduced wide characters in data";
                        $converted_input .= $input;
                    }
                    $data = substr($converted_input, 0, $block_size, '');
                    $len = length $data;
                    $eof = 1 if ($eof_t and !$len);
                }
                else {
                    $debug and $debug & 16384 and
                        _debug "reading block at offset ".CORE::tell($fh)." block_size: $block_size";

                    $len = CORE::read($fh, $data, $block_size);

                    if ($len) {
                        $debug and $debug & 16384 and _debug "block read, size: $len";

                        utf8::downgrade($data, 1)
                                or croak "wide characters unexpectedly read from file";

                        $debug and $debug & 16384 and length $data != $len and
                            _debug "read data changed size on downgrade to " . length($data);
                    }
                    else {
                        unless (defined $len) {
                            $sftp->_set_error(SFTP_ERR_LOCAL_READ_ERROR,
                                              "Couldn't read from local file '$local'", $!);
                            last OK;
                        }
                        $eof = 1;
                    }
                }

                my $nextoff = $writeoff + $len;

                if (defined $cb) {
                    $lsize = $nextoff if $nextoff > $lsize;
                    $cb->($sftp, $data, $writeoff, $lsize);

                    last OK if $sftp->{_error};

                    utf8::downgrade($data, 1) or croak "callback introduced wide characters in data";

                    $len = length $data;
                    $nextoff = $writeoff + $len;
                }

                if ($len) {
                    if ($sparse and $data =~ /^\x{00}*$/s) {
                        $last_block_was_zeros = 1;
                        $debug and $debug & 16384 and _debug "skipping zeros block at offset $writeoff, length $len";
                    }
                    else {
                        $debug and $debug & 16384 and _debug "writing block at offset $writeoff, length $len";

                        my $id = $sftp->_queue_msg(SSH2_FXP_WRITE, str => $rid,
                                                   uint64 => $writeoff, str => $data);
                        push @msgid, $id;
                        $last_block_was_zeros = 0;
                    }
                    $writeoff = $nextoff;
                }
            }

            last if ($eof and !@msgid);

            next unless  ($eof
                          or @msgid >= $queue_size
                          or $sftp->_do_io(0));

            my $id = shift @msgid;
            unless ($sftp->_get_status_msg_and_check($id,
                                                     SFTP_ERR_REMOTE_WRITE_FAILED,
                                                     "Couldn't write to remote file")) {
                last OK;
            }
        }

        CORE::close $fh unless $local_is_fh;

        $sftp->_get_msg for (@msgid);

        $sftp->truncate($rfh, $writeoff)
            if $last_block_was_zeros and not $sftp->{_error};

        $sftp->_with_save_error(close => $rfh);

        goto CLEANUP if $sftp->{_error};

        # set perm for servers that does not support setting
        # permissions on open files and also atime and mtime:
        if ($copy_time or ($late_set_perm and defined $perm)) {
            $attrs->set_perm unless $late_set_perm and defined $perm;
            $attrs->set_amtime($latime, $lmtime) if $copy_time;
            $sftp->_with_best_effort($best_effort, setstat => $remote, $attrs) or goto CLEANUP
        }

        if ($atomic) {
            $sftp->rename($remote, $atomic_remote,
                          overwrite => $overwrite,
                          numbered => $atomic_numbered) or goto CLEANUP;
        }

    CLEANUP:
        if ($cleanup and $sftp->{_error}) {
            warn "cleanup $remote";
            $sftp->_with_save_error(remove => $remote);
        }
    };
    $sftp->_ok_or_autodie;
}

1;

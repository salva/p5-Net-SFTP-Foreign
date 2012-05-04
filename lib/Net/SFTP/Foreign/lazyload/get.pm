use strict;
use warnings;
no warnings 'redefine';

our $debug;

sub get {
    @_ >= 2 or croak 'Usage: $sftp->get($remote, $local, %opts)';
    ${^TAINT} and &_catch_tainted_args;

    my ($sftp, $remote, $local, %opts) = @_;
    defined $remote or croak "remote file path is undefined";

    $sftp->_clear_error_and_status;

    $remote = $sftp->_rel2abs($remote);
    $local = _file_part($remote) unless defined $local;
    my $local_is_fh = (ref $local and $local->isa('GLOB'));

    my $cb = delete $opts{callback};
    my $umask = delete $opts{umask};
    my $perm = delete $opts{perm};
    my $copy_perm = delete $opts{exists $opts{copy_perm} ? 'copy_perm' : 'copy_perms'};
    my $copy_time = delete $opts{copy_time};
    my $overwrite = delete $opts{overwrite};
    my $resume = delete $opts{resume};
    my $append = delete $opts{append};
    my $block_size = delete $opts{block_size} || $sftp->{_block_size};
    my $queue_size = delete $opts{queue_size} || $sftp->{_queue_size};
    my $dont_save = delete $opts{dont_save};
    my $conversion = delete $opts{conversion};
    my $numbered = delete $opts{numbered};
    my $cleanup = delete $opts{cleanup};
    my $atomic = delete $opts{atomic};
    my $best_effort = delete $opts{best_effort};

    croak "'perm' and 'copy_perm' options can not be used simultaneously"
	if (defined $perm and defined $copy_perm);
    croak "'resume' and 'append' options can not be used simultaneously"
	if ($resume and $append);
    croak "'numbered' can not be used with 'overwrite', 'resume' or 'append'"
	if ($numbered and ($overwrite or $resume or $append));
    croak "'atomic' can not be used with 'resume' or 'append'"
        if ($atomic and ($resume or $append));
    if ($local_is_fh) {
	my $append = 'option can not be used when target is a file handle';
	$resume and croak "'resume' $append";
	$overwrite and croak "'overwrite' $append";
	$numbered and croak "'numbered' $append";
	$dont_save and croak "'dont_save' $append";
        $atomic and croak "'croak' $append";
    }
    %opts and _croak_bad_options(keys %opts);

    if ($resume and $conversion) {
        carp "resume option is useless when data conversion has also been requested";
        undef $resume;
    }

    $overwrite = 1 unless (defined $overwrite or $local_is_fh or $numbered);
    $copy_perm = 1 unless (defined $perm or defined $copy_perm or $local_is_fh);
    $copy_time = 1 unless (defined $copy_time or $local_is_fh);
    $cleanup = ($atomic || $numbered) unless defined $cleanup;

    my $a = do {
        local $sftp->{_autodie};
        $sftp->stat($remote);
    };
    my ($rperm, $size, $atime, $mtime) = ($a ? ($a->perm, $a->size, $a->atime, $a->mtime) : ());
    $size = -1 unless defined $size;

    if ($copy_time and not defined $atime) {
        if ($best_effort) {
            undef $copy_time;
        }
        else {
            $sftp->_ok_or_autodie and $sftp->_set_error(SFTP_ERR_REMOTE_STAT_FAILED,
                                                        "Not enough information on stat, amtime not included");
            return undef;
        }
    }

    $umask = (defined $perm ? 0 : umask) unless defined $umask;
    if ($copy_perm) {
        if (defined $rperm) {
            $perm = $rperm;
        }
        elsif ($best_effort) {
            undef $copy_perm
        }
        else {
            $sftp->_ok_or_autodie and $sftp->_set_error(SFTP_ERR_REMOTE_STAT_FAILED,
                                                        "Not enough information on stat, mode not included");
            return undef
        }
    }
    $perm &= ~$umask if defined $perm;

    $sftp->_clear_error_and_status;

    if ($resume and $resume eq 'auto') {
        undef $resume;
        if (defined $mtime) {
            if (my @lstat = CORE::stat $local) {
                $resume = ($mtime <= $lstat[9]);
            }
        }
    }

    my ($atomic_numbered, $atomic_local, $atomic_cleanup);

    my ($rfh, $fh);
    my $askoff = 0;
    my $lstart = 0;

    if ($dont_save) {
        $rfh = $sftp->open($remote, SSH2_FXF_READ);
        defined $rfh or return undef;
    }
    else {
        unless ($local_is_fh or $overwrite or $append or $resume or $numbered) {
	    if (-e $local) {
                $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
                                  "local file $local already exists");
                return undef
	    }
        }

        if ($atomic) {
            $atomic_local = $local;
            $local .= sprintf("(%d).tmp", rand(10000));
            $atomic_numbered = $numbered;
            $numbered = 1;
            $debug and $debug & 128 and _debug("temporal local file name: $local");
        }

        if ($resume) {
            if (CORE::open $fh, '+<', $local) {
                binmode $fh;
		CORE::seek($fh, 0, 2);
                $askoff = CORE::tell $fh;
                if ($askoff < 0) {
                    # something is going really wrong here, fall
                    # back to non-resuming mode...
                    $askoff = 0;
                    undef $fh;
                }
                else {
                    if ($size >=0 and $askoff > $size) {
                        $sftp->_set_error(SFTP_ERR_LOCAL_BIGGER_THAN_REMOTE,
                                          "Couldn't resume transfer, local file is bigger than remote");
                        return undef;
                    }
                    $size == $askoff and return 1;
                }
            }
        }

        # we open the remote file so late in order to skip it when
        # resuming an already completed transfer:
        $rfh = $sftp->open($remote, SSH2_FXF_READ);
        defined $rfh or return undef;

	unless (defined $fh) {
	    if ($local_is_fh) {
		$fh = $local;
		local ($@, $SIG{__DIE__}, $SIG{__WARN__});
		eval { $lstart = CORE::tell($fh) };
		$lstart = 0 unless ($lstart and $lstart > 0);
	    }
	    else {
                my $flags = Fcntl::O_CREAT|Fcntl::O_WRONLY;
                $flags |= Fcntl::O_APPEND if $append;
                $flags |= Fcntl::O_EXCL if ($numbered or (!$overwrite and !$append));
                unlink $local if $overwrite;
                while (1) {
                    my $open_perm = (defined $perm ? $perm : 0666);
                    my $save = _umask_save_and_set($umask);
                    sysopen ($fh, $local, $flags, $open_perm) and last;
                    unless ($numbered and -e $local) {
                        $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
                                          "Can't open $local", $!);
                        return undef;
                    }
                    _inc_numbered($local);
                }
                $$numbered = $local if ref $numbered;
		binmode $fh;
		$lstart = sysseek($fh, 0, 1) if $append;
	    }
	}

	if (defined $perm) {
            my $error;
	    do {
                local ($@, $SIG{__DIE__}, $SIG{__WARN__});
                unless (eval { CORE::chmod($perm, $local) > 0 }) {
                    $error = ($@ ? $@ : $!);
                }
            };
	    if ($error and !$best_effort) {
                unlink $local unless $resume or $append;
		$sftp->_set_error(SFTP_ERR_LOCAL_CHMOD_FAILED,
				  "Can't chmod $local", $error);
		return undef
	    }
	}
    }

    my $converter = _gen_converter $conversion;

    my $rid = $sftp->_rid($rfh);
    defined $rid or die "internal error: rid not defined";

    my @msgid;
    my @askoff;
    my $loff = $askoff;
    my $adjustment = 0;
    my $n = 0;
    local $\;
    do {
        # Disable autodie here in order to do not leave unhandled
        # responses queued on the connection in case of failure.
        local $sftp->{_autodie};

        # Again, once this point is reached, all code paths should end
        # through the CLEANUP block.

        while (1) {
            # request a new block if queue is not full
            while (!@msgid or (($size == -1 or $size > $askoff) and @msgid < $queue_size and $n != 1)) {

                my $id = $sftp->_queue_msg(SSH2_FXP_READ, str=> $rid,
                                           uint64 => $askoff, uint32 => $block_size);
                push @msgid, $id;
                push @askoff, $askoff;
                $askoff += $block_size;
                $n++;
            }

            my $eid = shift @msgid;
            my $roff = shift @askoff;

            my $msg = $sftp->_get_msg_and_check(SSH2_FXP_DATA, $eid,
                                                SFTP_ERR_REMOTE_READ_FAILED,
                                                "Couldn't read from remote file");

            unless ($msg) {
                if ($sftp->{_status} == SSH2_FX_EOF) {
                    $sftp->_set_error();
                    $roff != $loff and next;
                }
                last;
            }

            my $data = _buf_shift_str($msg);
            my $len = length $data;

            if ($roff != $loff or !$len) {
                $sftp->_set_error(SFTP_ERR_REMOTE_BLOCK_TOO_SMALL,
                                  "remote packet received is too small" );
                last;
            }

            $loff += $len;
            if ($len < $block_size) {
                $block_size = $len < 2048 ? 2048 : $len;
                $askoff = $loff;
            }

            my $adjustment_before = $adjustment;
            $adjustment += $converter->($data) if $converter;

            if (length($data) and defined $cb) {
                # $size = $loff if ($loff > $size and $size != -1);
                $cb->($sftp, $data,
                      $lstart + $roff + $adjustment_before,
                      $lstart + $size + $adjustment);

                last if $sftp->{_error};
            }

            if (length($data) and !$dont_save) {
                unless (print $fh $data) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                                      "unable to write data to local file $local", $!);
                    last;
                }
            }
        }

        $sftp->_get_msg for (@msgid);

        goto CLEANUP if $sftp->{_error};

        # if a converter is in place, and aditional call has to be
        # performed in order to flush any pending buffered data
        if ($converter) {
            my $data = '';
            my $adjustment_before = $adjustment;
            $adjustment += $converter->($data);

            if (length($data) and defined $cb) {
                # $size = $loff if ($loff > $size and $size != -1);
                $cb->($sftp, $data, $askoff + $adjustment_before, $size + $adjustment);
                goto CLEANUP if $sftp->{_error};
            }

            if (length($data) and !$dont_save) {
                unless (print $fh $data) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                                      "unable to write data to local file $local", $!);
                    goto CLEANUP;
                }
            }
        }

        # we call the callback one last time with an empty string;
        if (defined $cb) {
            my $data = '';
            $cb->($sftp, $data, $askoff + $adjustment, $size + $adjustment);
            return undef if $sftp->{_error};
            if (length($data) and !$dont_save) {
                unless (print $fh $data) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                                      "unable to write data to local file $local", $!);
                    goto CLEANUP;
                }
            }
        }

        unless ($dont_save) {
            unless ($local_is_fh or CORE::close $fh) {
                $sftp->_set_error(SFTP_ERR_LOCAL_WRITE_FAILED,
                                  "unable to write data to local file $local", $!);
                goto CLEANUP;
            }

            # we can be running on taint mode, so some checks are
            # performed to untaint data from the remote side.

            if ($copy_time) {
                unless (CORE::utime($atime, $mtime, $local) or $best_effort) {
                    $sftp->_set_error(SFTP_ERR_LOCAL_UTIME_FAILED,
                                      "Can't utime $local", $!);
                    goto CLEANUP;
                }
            }

            if ($atomic) {
                if (!$overwrite) {
                    while (1) {
                        # performing a non-overwriting atomic rename is
                        # quite burdensome: first, link is tried, if that
                        # fails, non-overwriting is favoured over
                        # atomicity and an empty file is used to lock the
                        # path before atempting an overwriting rename.
                        if (link $local, $atomic_local) {
                            unlink $local;
                            last;
                        }
                        my $err = $!;
                        unless (-e $atomic_local) {
                            if (sysopen my $lock, $atomic_local,
                                Fcntl::O_CREAT|Fcntl::O_EXCL|Fcntl::O_WRONLY,
                                0600) {
                                $atomic_cleanup = 1;
                                goto OVERWRITE;
                            }
                            $err = $!;
                            unless (-e $atomic_local) {
                                $sftp->_set_error(SFTP_ERR_LOCAL_OPEN_FAILED,
                                                  "Can't open $local", $err);
                                goto CLEANUP;
                            }
                        }
                        unless ($numbered) {
                            $sftp->_set_error(SFTP_ERR_LOCAL_ALREADY_EXISTS,
                                              "local file $atomic_local already exists");
                            goto CLEANUP;
                        }
                        _inc_numbered($atomic_local);
                    }
                }
                else {
                OVERWRITE:
                    unless (CORE::rename $local, $atomic_local) {
                        $sftp->_set_error(SFTP_ERR_LOCAL_RENAME_FAILED,
                                          "Unable to rename temporal file to its final position '$atomic_local'", $!);
                        goto CLEANUP;
                    }
                }
                $$atomic_numbered = $local if ref $atomic_numbered;
            }

        CLEANUP:
            if ($cleanup and $sftp->{_error}) {
                unlink $local;
                unlink $atomic_local if $atomic_cleanup;
            }
        }
    }; # autodie flag is restored here!

    $sftp->_ok_or_autodie;
}

1;

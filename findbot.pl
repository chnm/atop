#!/usr/bin/perl
# The above line may need to be changed to point at your version of Perl
#
#	This script attempts to find malicious files/scripts on your machine.
#	It specifically looks for spambots that we're aware of, as well
#	as "suspicious" constructs in various scripting languages.
#
#	Normally it should be run as root.
#
#	By default, findbot.pl scans the directories /tmp, /usr/tmp, /home and
#	/var/www.  This script isn't fast.  So if you know where to look you can
#	speed things up by giving just the directories that you suspect has the
#	malware.
#
#	You can often find out what user is infected by using:
#		lsof -i | grep smtp
#	and looking for processes that are NOT your mail server.
#
#	If you're successful finding the user, you need to look everywhere the user
#	has write permissions - and you can run findbot.pl faster, by something like:
#
#	findbot.pl /tmp /usr/tmp /home/<user> <user's web directory>
#
#	There are two types of "detections" - "suspicious files" are files that contain
#	things that -may- be malicious.
#	"malware" is definitely malicious software.
#
#	This script needs the following command line utilities.  It will not run
#	if it can't find them, you will have to install them yourself:
#		- "md5sum" (Linux) or "md5" (FreeBSD etc) this appears to be standard
#			core utilities.
#		- "strings" - on Linux this is in the "binutils" package
#		- "file" - on Linux this is in the "file" package.
#
# Usage:
#	findbot.pl [directories...]
#
#	If a list of directories is supplied, it's used, otherwise,
#	/tmp, /usr/tmp, /home and /var/www are use by default.
#
# Very simple web malware detection module.
# Version 0.02 2013/01/02 Ray
# .01 -> .02:
#	- more strings of bad software
#	- search for encoded perl scripts
# .02 -> .03: 2013/01/10 Ray
#	- speed up
#	- MD5 stuff
# .03 -> .04: 2013/01/13 Ray
#	- improved docs
# .04 -> .005: 2013/01/20 Ray
#	- more patterns
#	- MAXLINES way too small

my $access = '(\.htaccess)';
my $accesspat = '(RewriteRule)';
my $scripts = '\.(php|pl|cgi|bak)$';
my $scriptpat = '(r57|c99|web shell|passthru|shell_exec|phpinfo|base64_decode|edoced_46esab|PHPShell|EHLO|MAIL FROM|RCPT TO|fsockopen|\$random_num\.qmail|getmxrr)';

my @defaultdirs = ('/tmp', '/usr/tmp', '/home', '/var/www');

my $MAXLINES = 400;

my($strings, $md5sum, $file, %badhash);

&inithelpers;
&badhashes;

#my $executable = '^(sshd|cache|exim|sh|bash)$';

if ($ARGV[0] =~ /^-/) {
    my $l = join(',', @defaultdirs);
    print STDERR <<EOF;
usage: $0 [directories to scan...]

    If no directories specified, script uses:
$l
EOF
    exit 0;
}

  

if (!scalar(@ARGV)) {
    push(@ARGV, @defaultdirs);
}

for my $dir (@ARGV) {
    &recursion($dir);
}

sub recursion {
    my ($dir) = @_;
    my (@list);
    if (!opendir(I, "$dir")) {
	return if $! =~ /no such file/i;
	print STDERR "$dir: Can't open: $!, skipping\n";
	return;
    }
    @list = readdir(I);
    closedir(I);
    for my $mfile (@list) {
	next if $mfile =~ /^\.\.?$/;	# skip . and ..
	my $cf = $currentfile = "$dir/$mfile";

	$cf =~ s/'/'"'"'/g;	# hide single-quotes in filename
	$cf = "'$cf'";		# bury in single-quotes

	if (-d $currentfile && ! -l $currentfile) {
	    &recursion($currentfile);	# don't scan symlinks
	    next;
	} 
	next if ! -f $currentfile;
	if ($mfile =~ /$scripts/) {
	    &scanfile($currentfile, $scriptpat);
	} elsif ($mfile =~ /$access/) {
	    &scanfile($currentfile, $accesspat);
	}

	# up to here it's fast.

	next if -s $currentfile > 1000000 || -s $currentfile < 2000;

#print STDERR "$currentfile\n";

	my $type = `$file $cf`;

	if ($type =~ /(ELF|\d\d-bit).*executable/ || $currentfile =~ /\.(exe|scr|com)$/) {
#print STDERR "cf: $cf\n";
	    my $checksum = `$md5sum $cf`;
	    chomp($checksum);
	    $checksum =~ s/\s.*//;
	    if ($badhash{$checksum}) {
		print STDERR "$currentfile: Malware detected!\n";
		next;
	    }

	    my $strings = `$strings $cf`;
	    if ($strings =~ /\/usr\/bin\/perl/sm) {
		print STDERR "$currentfile: possible binary-encoded-perl\n";
		next;
	    }
	}
    }
}

sub scanfile {
    my ($currentfile, $patterns) = @_;
#print $currentfile, "\n";
    open(I, "<$currentfile") || next;
    my $linecount = 1;
    while(<I>) {
	chomp;
	if ($_ =~ /$patterns/) {
	    my $pat = $1;
	    my $string = $_;
	    if ($string =~ /^(.*)$pat(.*)$/) {
		$string = substr($1, length($1)-10, 10) .
				      $pat .
				      substr($2, 0, 10);
	    }
	    #$string =~ s/^.*(.{,10}$pat.{,10}).*$/... $1 .../;
	    print "$currentfile: Suspicious($pat): $string\n";
	    last;
	}
	last if $linecount++ > $MAXLINES;
    }
    close(I);
}

sub inithelpers {
    if (-x '/usr/bin/md5sum') {
	$md5sum = '/usr/bin/md5sum';
    } elsif (-x '/sbin/md5') {
	$md5sum = '/sbin/md5 -q';
    }
    for my $x (('/bin', '/usr/bin')) {
	if (-x "$x/strings") {
	    $strings = "$x/strings";
	}
	if (-x "$x/file") {
	    $file = "$x/file";
	}
    }
    die "Can't find md5 checksumming tool - normally in Linux coretools package" if !$md5sum;
    die "Can't find strings tool - normally in Linux bintools package" if !$strings;
    die "Can't find file tool - normally in file package" if !$file;
}

sub badhashes {
    map { $badhash{$_} = 1; } ((
    	'f7536bb412d6c4573fd6fd819e1b07bb',
	'0fdb34f48166dae57ff410d723efd3f7',
	'396d1fb94d79b732f6ab2fa6c5f3ed39',
	'fd3c01133946d59ace4fdb49dde93268', #Directmailer .exe Windows binary
	));
}

exitcode=0
lighttpdpid=0
prepare_test () {
  test -x $srcdir/conformance.pl || exit 77

  NAME=`basename $0 | sed s/\.sh$//`
  if which mktemp > /dev/null; then
    TMPFILE=`mktemp /tmp/$NAME.XXXXXX` || exit 1;
  else
    TMPFILE=/tmp/$NAME.XXXXXX
  fi

  if test x$top_builddir != x; then
	  # not in stand-alone mode
  	if test -f /tmp/lighttpd/lighttpd.pid; then
		kill `cat /tmp/lighttpd/lighttpd.pid`
		rm -f /tmp/lighttpd/lighttpd.pid
 	fi
  
	# start webserver
	CONF=`echo $0 | sed s/\.sh$/.conf/`
	#VALGRIND='valgrind --tool=memcheck --logfile=lighttpd' 
	VALGRIND=
	if test -e $CONF; then
	  $VALGRIND $top_builddir/src/lighttpd -f $CONF 
	else
	  $VALGRIND $top_builddir/src/lighttpd -f $srcdir/lighttpd.conf 
	fi
  	test x$? = x0 || exit 1

	# ps ax > $NAME.psax
  fi
}

run_test_script () {
  if test x$top_builddir = x; then
    cat $TMPFILE | $srcdir/conformance.pl standalone > $NAME.out
  else 
    cat $TMPFILE | $srcdir/conformance.pl > $NAME.out
  fi
  
  exitcode=$?
}

run_test_exit () {
  if test x$top_builddir != x; then
    # stop webserver
    kill `cat /tmp/lighttpd/lighttpd.pid` || exit 1
    rm -f /tmp/lighttpd/lighttpd.pid
  fi

  if test x$exitcode = x0; then 
  	rm $NAME.out; 
  fi; 
  rm -f $TMPFILE
  
  exit $exitcode;
}

run_test () {
  run_test_script
  run_test_exit
}

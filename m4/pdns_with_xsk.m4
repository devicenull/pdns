AC_DEFUN([PDNS_WITH_XSK],[
  AC_MSG_CHECKING([if we have AF_XDP / XSK support])
  AC_ARG_WITH([xsk],
    AS_HELP_STRING([--with-xsk],[enable AF_XDP / XSK support @<:@default=auto@:>@]),
    [with_xsk=$withval],
    [with_xsk=auto],
  )
  AC_MSG_RESULT([$with_xsk])

  AS_IF([test "x$with_xsk" != "xno"], [
    PKG_CHECK_MODULES([LIBBPF], [libbpf], [have_libbpf=yes], [have_libbpf=no])
    PKG_CHECK_MODULES([LIBXDP], [libxdp], [have_libxdp=yes], [have_libxdp=no])
  ], [
    have_libbpf=no
    have_libxdp=no
  ])

  AS_IF([test "x$with_xsk" = "xyes"], [
    AS_IF([test "x$have_libbpf" != "xyes"], [
      AC_MSG_ERROR([XSK support requested but libbpf was not found])
    ])
    AS_IF([test "x$have_libxdp" != "xyes"], [
      AC_MSG_ERROR([XSK support requested but libxdp was not found])
    ])
  ])

  AM_CONDITIONAL([HAVE_XSK], [test "x$have_libbpf" = "xyes" -a "x$have_libxdp" = "xyes"])
  AS_IF([test "x$have_libbpf" = "xyes" -a "x$have_libxdp" = "xyes"], [
    AC_DEFINE([HAVE_BPF], [1], [Define if using libbpf.])
    AC_DEFINE([HAVE_XDP], [1], [Define if using libxdp.])
    AC_DEFINE([HAVE_XSK], [1], [Define if using AF_XDP / XSK.])
    save_LIBS="$LIBS"
    save_CXXFLAGS="$CXXFLAGS"
    CXXFLAGS="$CXXFLAGS $LIBBPF_CFLAGS"
    LIBS="$LIBS $LIBBPF_LIBS"
    AC_CHECK_FUNCS([bpf_xdp_query], [AC_DEFINE([HAVE_BPF_XDP_QUERY], [1], [Define if bpf_xdp_query is available.])])
    LIBS="$save_LIBS"
    CXXFLAGS="$save_CXXFLAGS"
  ])
])

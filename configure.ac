# Required initializer
AC_INIT(mod_diary, 0.2)

# Automake initialization
AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER(config.h)

# Add a test for a compiler.
AC_PROG_CC
AM_PROG_LIBTOOL

AC_ARG_WITH(apxs,
			[  --with-apxs=FILE      pathname to the Apache apxs tool ],
            ,[with_apxs="no"])
AC_MSG_CHECKING(for apxs tool)
if test "$with_apxs" = "no"; then
    AC_MSG_ERROR( You need to specify the apxs file using --with-apxs)
else
    if test -e $with_apxs; then
        apxs=$with_apxs
        AC_MSG_RESULT(APXS found!)
    else
        AC_MSG_ERROR( $with_apxs not found.  Check the value you specified with --with-apxs)
    fi
fi
AC_SUBST(apxs)

AC_ARG_WITH(discount,
			[  --with-discount=DIR    discount directory ],
            ,[with_discount="/usr"])
AC_MSG_CHECKING(for discount directory)
if test -e $with_discount/include/mkdio.h -o -e $with_discount/include/*/mkdio.h; then
    discount_dir=$with_discount
    AC_MSG_RESULT(DISCOUNT found!)
else
    AC_MSG_ERROR( $with_discount not found.  Check the value you specified with --with-discount)
fi
AC_SUBST(discount_dir)

AC_ARG_WITH(clearsilver, [  --with-clearsilver=DIR    clearsilver directory ],,[with_clearsilver="/usr"])
AC_MSG_CHECKING(for clearsilver directory)
if test -e $with_clearsilver/include/ClearSilver/ClearSilver.h; then
    clearsilver_dir=$with_clearsilver
    AC_MSG_RESULT(CLEARSILVER found!)
else
    AC_MSG_ERROR( $with_clearsilver not found.  Check the value you specified with --with-clearsilver)
fi
AC_SUBST(clearsilver_dir)

# Write config.status and the Makefile
AC_OUTPUT(Makefile)

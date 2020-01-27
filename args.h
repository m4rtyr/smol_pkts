/**
 * @Author: S. Sharma <m4rtyr>
 * @Date:   2020-01-26T21:54:02-06:00
 * @Email:  silentcat@protonmail.com
 * @Last modified by:   m4rtyr
 * @Last modified time: 2020-01-26T21:57:35-06:00
 */

#ifndef ARGS_H
#define ARGS_H

#include <stdio.h>

#define PROCESS_ARG(A, X) { \
  if (!strcmp(argv[i], A)) { \
    X = argv[i+1]; \
  } \
}

#endif

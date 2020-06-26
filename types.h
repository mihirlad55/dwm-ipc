#ifndef TYPES_H_
#define TYPES_H_

#include <X11/Xlib.h>

typedef union {
  int i;
  unsigned int ui;
  float f;
  const void *v;
} Arg;


#endif //  TYPES_H_

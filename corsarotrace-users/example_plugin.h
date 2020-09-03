#ifndef CORSARO_EXAMPLE_PLUGIN_H_
#define CORSARO_EXAMPLE_PLUGIN_H_

#include "libcorsaro.h"
#include "libcorsaro_plugin.h"

corsaro_plugin_t *corsaro_example_alloc(void);
CORSARO_PLUGIN_GENERATE_PROTOTYPES(corsaro_example);


#endif

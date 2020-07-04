#ifndef YAJL_DUMPS_H_
#define YAJL_DUMPS_H_

#include "types.h"
#include <string.h>
#include <yajl/yajl_gen.h>

#define ystr(str) yajl_gen_string(gen, (unsigned char *)str, strlen(str))

int dump_tags(yajl_gen gen, const char *tags[], int tags_len);

int dump_client(yajl_gen gen, Client *c);

int dump_monitor(yajl_gen gen, Monitor *mon);

int dump_layouts(yajl_gen gen, const Layout layouts[], const int layouts_len);

int dump_tag_state(yajl_gen gen, TagState state);

int dump_tag_event(yajl_gen gen, int mon_num, TagState old_state,
                   TagState new_state);

int dump_client_change_event(yajl_gen gen, Client *old_client,
                             Client *new_client, int mon_num);

int dump_layout_change_event(yajl_gen gen, const int mon_num,
                             const char *old_symbol, const char *new_symbol);

int dump_error_message(yajl_gen gen, const char *reason);

#endif // YAJL_DUMPS_H_

#include "yajl_dumps.h"
#include <stdint.h>

int
dump_tags(yajl_gen gen, const char *tags[], int tags_len)
{
  yajl_gen_array_open(gen);
  for (int i = 0; i < tags_len; i++) {
    yajl_gen_map_open(gen);
    ystr("bit_mask"); yajl_gen_integer(gen, 1 << i);
    ystr("name"); ystr(tags[i]);
    yajl_gen_map_close(gen);
  }
  yajl_gen_array_close(gen);
  return 0;
}

int
dump_client(yajl_gen gen, Client *c)
{
  yajl_gen_map_open(gen);

  ystr("name"); ystr(c->name);
  ystr("mina"); yajl_gen_double(gen, c->mina);
  ystr("maxa"); yajl_gen_double(gen, c->maxa);
  ystr("tags"); yajl_gen_integer(gen, c->tags);
  ystr("window_id"); yajl_gen_integer(gen, c->win);
  ystr("monitor_number"); yajl_gen_integer(gen, c->mon->num);

  ystr("size");
  yajl_gen_map_open(gen);
  ystr("current");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->x);
  ystr("y"); yajl_gen_integer(gen, c->y);
  ystr("width"); yajl_gen_integer(gen, c->w);
  ystr("height"); yajl_gen_integer(gen, c->h);
  yajl_gen_map_close(gen);
  ystr("old");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, c->oldx);
  ystr("y"); yajl_gen_integer(gen, c->oldy);
  ystr("width"); yajl_gen_integer(gen, c->oldw);
  ystr("height"); yajl_gen_integer(gen, c->oldh);
  yajl_gen_map_close(gen);
  yajl_gen_map_close(gen);

  ystr("size_hints");
  yajl_gen_map_open(gen);
  ystr("base_width"); yajl_gen_integer(gen, c->basew);
  ystr("base_height"); yajl_gen_integer(gen, c->baseh);
  ystr("increase_width"); yajl_gen_integer(gen, c->incw);
  ystr("increase_height"); yajl_gen_integer(gen, c->inch);
  ystr("max_width"); yajl_gen_integer(gen, c->maxw);
  ystr("max_height"); yajl_gen_integer(gen, c->maxh);
  ystr("min_width"); yajl_gen_integer(gen, c->minw);
  ystr("min_height"); yajl_gen_integer(gen, c->minh);
  yajl_gen_map_close(gen);

  ystr("border");
  yajl_gen_map_open(gen);
  ystr("current_width"); yajl_gen_integer(gen, c->bw);
  ystr("old_width"); yajl_gen_integer(gen, c->oldbw);
  yajl_gen_map_close(gen);

  ystr("states");
  yajl_gen_map_open(gen);
  ystr("is_fixed"); yajl_gen_bool(gen, c->isfixed);
  ystr("is_floating"); yajl_gen_bool(gen, c->isfloating);
  ystr("is_urgent"); yajl_gen_bool(gen, c->isurgent);
  ystr("is_fullscreen"); yajl_gen_bool(gen, c->isfullscreen);
  ystr("never_focus"); yajl_gen_bool(gen, c->neverfocus);
  ystr("old_state"); yajl_gen_bool(gen, c->oldstate);
  yajl_gen_map_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

int
dump_monitor(yajl_gen gen, Monitor *mon)
{
  yajl_gen_map_open(gen);

  ystr("layout_symbol"); ystr(mon->ltsymbol);
  ystr("mfact"); yajl_gen_double(gen, mon->mfact);
  ystr("nmaster"); yajl_gen_integer(gen, mon->nmaster);
  ystr("num"); yajl_gen_integer(gen, mon->num);
  ystr("bar_y"); yajl_gen_integer(gen, mon->by);
  ystr("show_bar"); yajl_gen_bool(gen, mon->showbar);
  ystr("top_bar"); yajl_gen_bool(gen, mon->topbar);

  ystr("screen");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, mon->mx);
  ystr("y"); yajl_gen_integer(gen, mon->my);
  ystr("width"); yajl_gen_integer(gen, mon->mw);
  ystr("height"); yajl_gen_integer(gen, mon->mh);
  yajl_gen_map_close(gen);

  ystr("window");
  yajl_gen_map_open(gen);
  ystr("x"); yajl_gen_integer(gen, mon->wx);
  ystr("y"); yajl_gen_integer(gen, mon->wy);
  ystr("width"); yajl_gen_integer(gen, mon->ww);
  ystr("height"); yajl_gen_integer(gen, mon->wh);
  yajl_gen_map_close(gen);

  ystr("tag_set");
  yajl_gen_map_open(gen);
  ystr("old"); yajl_gen_integer(gen, mon->tagset[mon->seltags ^ 1]);
  ystr("current"); yajl_gen_integer(gen, mon->tagset[mon->seltags]);
  yajl_gen_map_close(gen);

  ystr("layout");
  yajl_gen_map_open(gen);
  ystr("old"); ystr(mon->lt[mon->sellt ^ 1]->symbol);
  ystr("current"); ystr(mon->lt[mon->sellt]->symbol);
  yajl_gen_map_close(gen);

  ystr("selected_client"); yajl_gen_integer(gen, mon->sel->win);

  ystr("stack");
  yajl_gen_array_open(gen);
  for (Client* c = mon->clients; c; c = c->snext)
    yajl_gen_integer(gen, c->win);
  yajl_gen_array_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

int
dump_layouts(yajl_gen gen, const Layout layouts[], const int layouts_len)
{
  yajl_gen_array_open(gen);

  for (int i = 0; i < layouts_len; i++) {
    yajl_gen_map_open(gen);
    ystr("layout_symbol");
    ystr(layouts[i].symbol);
    ystr("layout_address");
    yajl_gen_integer(gen, (intptr_t)&layouts[i]);
    yajl_gen_map_close(gen);
  }

  yajl_gen_array_close(gen);

  return 0;
}

int
dump_tag_state(yajl_gen gen, TagState state)
{
  yajl_gen_map_open(gen);
  ystr("selected"); yajl_gen_integer(gen, state.selected);
  ystr("occupied"); yajl_gen_integer(gen, state.occupied);
  ystr("urgent"); yajl_gen_integer(gen, state.urgent);
  yajl_gen_map_close(gen);

  return 0;
}

int
dump_tag_event(yajl_gen gen, int mon_num, TagState old_state,
        TagState new_state)
{
  yajl_gen_map_open(gen);

  ystr("tag_change_event");
  yajl_gen_map_open(gen);

  ystr("monitor_number"); yajl_gen_integer(gen, mon_num);

  ystr("old"); dump_tag_state(gen, old_state);

  ystr("new"); dump_tag_state(gen, new_state);

  yajl_gen_map_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

int
dump_client_change_event(yajl_gen gen, Client *old_client, Client *new_client,
  int mon_num)
{
  yajl_gen_map_open(gen);

  ystr("selected_client_change_event");
  yajl_gen_map_open(gen);

  ystr("moniter_number"); yajl_gen_integer(gen, mon_num);

  ystr("old");
  if (old_client != NULL)
    yajl_gen_integer(gen, old_client->win);
  else
    yajl_gen_null(gen);

  ystr("new");
  if (new_client != NULL)
    yajl_gen_integer(gen, new_client->win);
  else
    yajl_gen_null(gen);

  yajl_gen_map_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

int
dump_layout_change_event(yajl_gen gen, const int mon_num,
    const char *old_symbol, const char *new_symbol)
{
  yajl_gen_map_open(gen);

  ystr("layout_change_event");
  yajl_gen_map_open(gen);

  ystr("monitor_number"); yajl_gen_integer(gen, mon_num);

  ystr("old"); ystr(old_symbol);

  ystr("new"); ystr(new_symbol);

  yajl_gen_map_close(gen);

  yajl_gen_map_close(gen);

  return 0;
}

int
dump_error_message(yajl_gen gen, const char *reason)
{
  yajl_gen_map_open(gen);

  ystr("result"); ystr("error");
  ystr("reason"); ystr(reason);

  yajl_gen_map_close(gen);

  return 0;
}

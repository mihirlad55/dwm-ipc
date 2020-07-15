#include "yajl_dumps.h"
#include <stdint.h>

int
dump_tags(yajl_gen gen, const char *tags[], int tags_len)
{
  YARR(
    for (int i = 0; i < tags_len; i++) {
      YMAP(
        YSTR("bit_mask"); YINT(1 << i);
        YSTR("name"); YSTR(tags[i]);
      )
    }
  )

  return 0;
}

int
dump_client(yajl_gen gen, Client *c)
{
  YMAP(
    YSTR("name"); YSTR(c->name);
    YSTR("tags"); YINT(c->tags);
    YSTR("window_id"); YINT(c->win);
    YSTR("monitor_number"); YINT(c->mon->num);

    YSTR("geometry"); YMAP(
      YSTR("current"); YMAP (
        YSTR("x"); YINT(c->x);
        YSTR("y"); YINT(c->y);
        YSTR("width"); YINT(c->w);
        YSTR("height"); YINT(c->h);
      )
      YSTR("old"); YMAP(
        YSTR("x"); YINT(c->oldx);
        YSTR("y"); YINT(c->oldy);
        YSTR("width"); YINT(c->oldw);
        YSTR("height"); YINT(c->oldh);
      )
    )

    YSTR("size_hints"); YMAP(
      YSTR("base"); YMAP(
        YSTR("width"); YINT(c->basew);
        YSTR("height"); YINT(c->baseh);
      )
      YSTR("step"); YMAP(
        YSTR("width"); YINT(c->incw);
        YSTR("height"); YINT(c->inch);
      )
      YSTR("max"); YMAP(
        YSTR("width"); YINT(c->maxw);
        YSTR("height"); YINT(c->maxh);
      )
      YSTR("min"); YMAP(
        YSTR("width"); YINT(c->minw);
        YSTR("height"); YINT(c->minh);
      )
      YSTR("aspect_ratio"); YMAP(
        YSTR("min"); YDOUBLE(c->mina);
        YSTR("max"); YDOUBLE(c->maxa);
      )
    )

    YSTR("border_width"); YMAP(
      YSTR("current"); YINT(c->bw);
      YSTR("old"); YINT(c->oldbw);
    )

    YSTR("states"); YMAP(
      YSTR("is_fixed"); YBOOL(c->isfixed);
      YSTR("is_floating"); YBOOL(c->isfloating);
      YSTR("is_urgent"); YBOOL(c->isurgent);
      YSTR("never_focus"); YBOOL(c->neverfocus);
      YSTR("old_state"); YBOOL(c->oldstate);
      YSTR("is_fullscreen"); YBOOL(c->isfullscreen);
    )
  )

  return 0;
}

int
dump_monitor(yajl_gen gen, Monitor *mon)
{
  YMAP(
    YSTR("master_factor"); YDOUBLE(mon->mfact);
    YSTR("num_master"); YINT(mon->nmaster);
    YSTR("num"); YINT(mon->num);

    YSTR("monitor_geometry"); YMAP(
      YSTR("x"); YINT(mon->mx);
      YSTR("y"); YINT(mon->my);
      YSTR("width"); YINT(mon->mw);
      YSTR("height"); YINT(mon->mh);
    )

    YSTR("window_geometry"); YMAP(
      YSTR("x"); YINT(mon->wx);
      YSTR("y"); YINT(mon->wy);
      YSTR("width"); YINT(mon->ww);
      YSTR("height"); YINT(mon->wh);
    )

    YSTR("tagset"); YMAP(
      YSTR("current");  YINT(mon->tagset[mon->seltags]);
      YSTR("old"); YINT(mon->tagset[mon->seltags ^ 1]);
    )

    YSTR("tag_state"); dump_tag_state(gen, mon->tagstate);

    YSTR("clients"); YMAP(
      YSTR("selected"); YINT(mon->sel->win);
      YSTR("stack"); YARR(
        for (Client* c = mon->stack; c; c = c->snext)
          YINT(c->win);
      )
      YSTR("all"); YARR(
        for (Client* c = mon->clients; c; c = c->snext)
          YINT(c->win);
      )
    )

    YSTR("layout"); YMAP(
      YSTR("symbol"); YMAP(
        YSTR("current"); YSTR(mon->ltsymbol);
        YSTR("old"); YSTR(mon->lastltsymbol);
      )
      YSTR("address"); YMAP(
        YSTR("current"); YINT((uintptr_t)mon->lt[mon->sellt]);
        YSTR("old"); YINT((uintptr_t)mon->lt[mon->sellt ^ 1]);
      )
    )

    YSTR("bar"); YMAP(
      YSTR("y"); YINT(mon->by);
      YSTR("is_shown"); YBOOL(mon->showbar);
      YSTR("is_top"); YBOOL(mon->topbar);
      YSTR("window_id"); YINT(mon->barwin);
    )
  )

  return 0;
}

int
dump_layouts(yajl_gen gen, const Layout layouts[], const int layouts_len)
{
  YARR(
    for (int i = 0; i < layouts_len; i++) {
      YMAP(
        YSTR("symbol"); YSTR(layouts[i].symbol);
        YSTR("address"); YINT((uintptr_t)(layouts + i));
      )
    }
  )

  return 0;
}

int
dump_tag_state(yajl_gen gen, TagState state)
{
  YMAP(
    YSTR("selected"); YINT(state.selected);
    YSTR("occupied"); YINT(state.occupied);
    YSTR("urgent"); YINT(state.urgent);
  )

  return 0;
}

int
dump_tag_event(yajl_gen gen, int mon_num, TagState old_state,
        TagState new_state)
{
  YMAP(
    YSTR("tag_change_event"); YMAP(
      YSTR("monitor_number"); YINT(mon_num);
      YSTR("old_state"); dump_tag_state(gen, old_state);
      YSTR("new_state"); dump_tag_state(gen, new_state);
    )
  )

  return 0;
}

int
dump_client_change_event(yajl_gen gen, Client *old_client, Client *new_client,
  int mon_num)
{
  YMAP(
    YSTR("selected_client_change_event"); YMAP(
      YSTR("moniter_number"); YINT(mon_num);
      YSTR("old_win_id"); old_client == NULL ? YNULL() : YINT(old_client->win);
      YSTR("new_win_id"); new_client == NULL ? YNULL() : YINT(new_client->win);
    )
  )

  return 0;
}

int
dump_layout_change_event(yajl_gen gen, const int mon_num,
    const char *old_symbol, const Layout *old_layout, const char* new_symbol,
    const Layout *new_layout)
{
  YMAP(
    YSTR("layout_change_event"); YMAP(
      YSTR("monitor_number"); YINT(mon_num);
      YSTR("old_symbol"); YSTR(old_symbol);
      YSTR("old_address"); YINT((uintptr_t)old_layout);
      YSTR("new_symbol"); YSTR(new_symbol);
      YSTR("new_address"); YINT((uintptr_t)new_layout);
    )
  )

  return 0;
}

int
dump_monitor_change_event(yajl_gen gen, const int last_mon_num,
    const int new_mon_num)
{
  YMAP(
    YSTR("monitor_change_event"); YMAP(
      YSTR("old_monitor_number"); YINT(last_mon_num);
      YSTR("new_monitor_number"); YINT(new_mon_num);
    )
  )
  return 0;
}

int
dump_error_message(yajl_gen gen, const char *reason)
{
  YMAP(
    YSTR("result"); YSTR("error");
    YSTR("reason"); YSTR(reason);
  )

  return 0;
}

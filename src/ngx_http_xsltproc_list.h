#ifndef _NGX_HTTP_XSLTPROC_LIST_INCLUDED_
#define _NGX_HTTP_XSLTPROC_LIST_INCLUDED_

typedef struct ngx_http_xsltproc_list ngx_http_xsltproc_list_t;
struct ngx_http_xsltproc_list {
    ngx_http_xsltproc_list_t *prev;
    ngx_http_xsltproc_list_t *next;
};

#define ngx_http_xsltproc_list_init(l)                                 \
    (l)->prev = l;                                                     \
    (l)->next = l

#define ngx_http_xsltproc_list_empty(l)                                \
    (l == (l)->prev)

#define ngx_http_xsltproc_list_insert_head(l, x)                       \
    (x)->next = (l)->next;                                             \
    (x)->next->prev = x;                                               \
    (x)->prev = l;                                                     \
    (l)->next = x

#define ngx_http_xsltproc_list_insert_after   ngx_http_xsltproc_list_insert_head

#define ngx_http_xsltproc_list_insert_tail(l, x)                       \
    (x)->prev = (l)->prev;                                             \
    (x)->prev->next = x;                                               \
    (x)->next = l;                                                     \
    (l)->prev = x

#define ngx_http_xsltproc_list_first(l)                                \
    (l)->next

#define ngx_http_xsltproc_list_last(l)                                 \
    (l)->prev

#define ngx_http_xsltproc_list_end(l)                                  \
    (l)

#define ngx_http_xsltproc_list_next(l)                                 \
    (l)->next

#define ngx_http_xsltproc_list_prev(l)                                 \
    (l)->prev

#define ngx_http_xsltproc_list_remove(x)                               \
    (x)->next->prev = (x)->prev;                                       \
    (x)->prev->next = (x)->next

#define ngx_http_xsltproc_list_split(h, q, n)                          \
    (n)->prev = (h)->prev;                                             \
    (n)->prev->next = n;                                               \
    (n)->next = q;                                                     \
    (h)->prev = (q)->prev;                                             \
    (h)->prev->next = h;                                               \
    (q)->prev = n

/* Merge two list */
#define ngx_http_xsltproc_list_merge(a, b)                             \
    (a)->prev->next = (b)->next;                                       \
    (b)->next->prev = (a)->prev;                                       \
    (a)->prev = (b)->prev;                                             \
    (a)->prev->next = a

void ngx_http_xsltproc_list_sort(ngx_http_xsltproc_list_t *list, int (*cmp)(const ngx_http_xsltproc_list_t *, const ngx_http_xsltproc_list_t *));

#endif /* _NGX_HTTP_XSLTPROC_LIST_H_INCLUDED_ */

#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_list.h"


void ngx_http_xsltproc_list_sort(ngx_http_xsltproc_list_t *list, int (*cmp)(const ngx_http_xsltproc_list_t *, const ngx_http_xsltproc_list_t *)) {
    ngx_http_xsltproc_list_t *el, *prev, *next;

    el = ngx_http_xsltproc_list_first(list);

    if (el == ngx_http_xsltproc_list_last(list)) {
        return;
    }

    for (el = ngx_http_xsltproc_list_next(el); el != ngx_http_xsltproc_list_end(list); el = next) {

        prev = ngx_http_xsltproc_list_prev(el);
        next = ngx_http_xsltproc_list_next(el);

        ngx_http_xsltproc_list_remove(el);

        do {
            if (cmp(prev, el) <= 0) {
                break;
            }

            prev = ngx_http_xsltproc_list_prev(prev);

        } while (prev != ngx_http_xsltproc_list_end(list));

        ngx_http_xsltproc_list_insert_after(prev, el);
    }
}

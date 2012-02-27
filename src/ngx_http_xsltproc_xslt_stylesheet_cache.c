#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_http_xsltproc_list_t xslt_stylesheet_cache;
static ngx_log_t *xslt_stylesheet_cache_log = NULL;

#ifdef NGX_DEBUG
static void print_cache_list(ngx_http_xsltproc_list_t *list) {
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;
    ngx_http_xsltproc_list_t            *el;

    ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_cache_log, 0,
                       "print_cache_list: %p",
                       list);

    for (
        el = ngx_http_xsltproc_list_first(list);
        el != ngx_http_xsltproc_list_end(list);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_stylesheet = (ngx_http_xsltproc_xslt_stylesheet_t *) el;

        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_cache_log, 0,
                           "print_cache_list: Cache element: \"%s\"",
                           xslt_stylesheet->uri);
    }
}
#endif

ngx_http_xsltproc_xslt_stylesheet_t *
ngx_http_xsltproc_xslt_stylesheet_cache_lookup(ngx_http_xsltproc_filter_loc_conf_t *cf, char *uri) {
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet = NULL;
    ngx_http_xsltproc_list_t            *el;
    int                                  found = 0;

#ifdef NGX_DEBUG
    print_cache_list(&xslt_stylesheet_cache);
#endif

    for (
        el = ngx_http_xsltproc_list_first(&xslt_stylesheet_cache);
        el != ngx_http_xsltproc_list_end(&xslt_stylesheet_cache);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_stylesheet = (ngx_http_xsltproc_xslt_stylesheet_t *) el;

        if (strcmp(xslt_stylesheet->uri, uri) == 0) {
#ifdef NGX_DEBUG
            ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_cache_log, 0,
                               "ngx_http_xsltproc_xslt_stylesheet_cache_lookup: stylesheet %s found in cache",
                               uri);
#endif

            found = 1;

            break;
        }
    }

    if (found && cf->stylesheet_check_if_modify == 1
        && ngx_http_xsltproc_xslt_stylesheet_is_updated(xslt_stylesheet)) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_cache_log, 0,
                           "ngx_http_xsltproc_xslt_stylesheet_cache_lookup: stylesheet %s expired",
                           uri);
#endif

#if (NGX_HTTP_XSLPROC_XSLT_DOCUMENT_CACHING && NGX_HTTP_XSLPROC_XSLT_KEYS_CACHING)
        ngx_http_xsltproc_xslt_keys_cache_expire(xslt_stylesheet->uri, xslt_stylesheet->mtime, NULL, 0);
#endif

        ngx_http_xsltproc_xslt_stylesheet_clear(xslt_stylesheet);
    }

    if (!found) {
        xslt_stylesheet = ngx_http_xsltproc_xslt_stylesheet_new(uri);
        ngx_http_xsltproc_list_insert_tail(&xslt_stylesheet_cache, (ngx_http_xsltproc_list_t *) xslt_stylesheet);
    }

#ifdef NGX_DEBUG
    print_cache_list(&xslt_stylesheet_cache);
#endif

    return xslt_stylesheet;
}

static void ngx_http_xsltproc_xslt_stylesheet_cache_free(void) {
    ngx_http_xsltproc_list_t *el;

    for (
        el = ngx_http_xsltproc_list_first(&xslt_stylesheet_cache);
        el != ngx_http_xsltproc_list_end(&xslt_stylesheet_cache);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        ngx_http_xsltproc_xslt_stylesheet_free((ngx_http_xsltproc_xslt_stylesheet_t *) el);
    }
}

int ngx_http_xsltproc_xslt_stylesheet_cache_init(ngx_log_t *log) {
    xslt_stylesheet_cache_log = log;

    ngx_http_xsltproc_list_init(&xslt_stylesheet_cache);

    return 0;
}

void ngx_http_xsltproc_xslt_stylesheet_cache_destroy(void) {
    ngx_http_xsltproc_xslt_stylesheet_cache_free();
}

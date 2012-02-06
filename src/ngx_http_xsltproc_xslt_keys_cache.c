#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_http_xsltproc_list_t xslt_keys_cache;
static ngx_log_t *xslt_keys_cache_log = NULL;

static ngx_http_xsltproc_xslt_keys_t *
ngx_http_xsltproc_xslt_keys_cache_lookup(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime)
{
    ngx_http_xsltproc_xslt_keys_t *xslt_keys = NULL;
    ngx_http_xsltproc_list_t      *el;

    for (
        el  = ngx_http_xsltproc_list_first(&xslt_keys_cache);
        el != ngx_http_xsltproc_list_end(&xslt_keys_cache);
        el  = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_keys = (ngx_http_xsltproc_xslt_keys_t *) el;

        if (strcmp(xslt_keys->stylesheet_uri, stylesheet_uri) != 0)
            continue;
        if (xslt_keys->stylesheet_mtime != stylesheet_mtime)
            continue;
        if (strcmp(xslt_keys->document_uri, document_uri) != 0)
            continue;
        if (xslt_keys->document_mtime != document_mtime)
            continue;

#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                           "ngx_http_xsltproc_xslt_keys_cache_lookup: keys for document %s is found in cache",
                           document_uri);
#endif

        return xslt_keys;
    }

    return NULL;
}

void
ngx_http_xsltproc_xslt_keys_cache_put(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime, xsltDocumentPtr xslt_document)
{
    ngx_http_xsltproc_xslt_keys_t *xslt_keys;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                       "ngx_http_xsltproc_xslt_keys_cache_put: stylesheet %s document %s",
                       stylesheet_uri, document_uri);
#endif

    xslt_keys = ngx_http_xsltproc_xslt_keys_cache_lookup(stylesheet_uri, stylesheet_mtime,
        document_uri, document_mtime);

    if (xslt_keys == NULL) {
        xslt_keys = ngx_http_xsltproc_xslt_keys_new(stylesheet_uri, stylesheet_mtime,
            document_uri, document_mtime, xslt_document);

        if (xslt_keys != NULL)
            ngx_http_xsltproc_list_insert_tail(&xslt_keys_cache, (ngx_http_xsltproc_list_t *) xslt_keys);
    }
}

void
ngx_http_xsltproc_xslt_keys_cache_get(ngx_http_xsltproc_list_t *xslt_keys_list, char *stylesheet_uri, time_t stylesheet_mtime)
{
    ngx_http_xsltproc_xslt_keys_t *xslt_keys, *xslt_keys_dup;
    ngx_http_xsltproc_list_t      *el;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                       "ngx_http_xsltproc_xslt_keys_cache_get: stylesheet %s %d",
                       stylesheet_uri, (int) stylesheet_mtime);
#endif

    ngx_http_xsltproc_list_init(xslt_keys_list);

    for (
        el = ngx_http_xsltproc_list_first(&xslt_keys_cache);
        el != ngx_http_xsltproc_list_end(&xslt_keys_cache);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_keys = (ngx_http_xsltproc_xslt_keys_t *) el;

        if (strcmp(xslt_keys->stylesheet_uri, stylesheet_uri) != 0)
            continue;
        if (xslt_keys->stylesheet_mtime != stylesheet_mtime)
            continue;

        if ((xslt_keys_dup = ngx_http_xsltproc_malloc(sizeof(ngx_http_xsltproc_xslt_keys_t))) == NULL) {
            return;
        }
        memcpy(xslt_keys_dup, xslt_keys, sizeof(ngx_http_xsltproc_xslt_keys_t));
        ngx_http_xsltproc_list_insert_tail(xslt_keys_list, (ngx_http_xsltproc_list_t *) xslt_keys_dup);

#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                           "ngx_http_xsltproc_xslt_keys_cache_get: keys %s for stylesheet %s is found in cache",
                           xslt_keys->document_uri, stylesheet_uri);
#endif
    }
}

void
ngx_http_xsltproc_xslt_keys_cache_expire(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime)
{
    ngx_http_xsltproc_xslt_keys_t *xslt_keys;
    ngx_http_xsltproc_list_t      *el;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                       "ngx_http_xsltproc_xslt_keys_cache_expire: stylesheet %s %d, document %p",
                       stylesheet_uri, (int) stylesheet_mtime, document_uri);
#endif

    el = ngx_http_xsltproc_list_first(&xslt_keys_cache);
    while (el != ngx_http_xsltproc_list_end(&xslt_keys_cache)) {
        xslt_keys = (ngx_http_xsltproc_xslt_keys_t *) el;

#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                           "ngx_http_xsltproc_xslt_keys_cache_expire: search stylesheet %s %d, document %s",
                           xslt_keys->stylesheet_uri, (int) xslt_keys->stylesheet_mtime, xslt_keys->document_uri);
#endif

        if (
            (stylesheet_uri == NULL || strcmp(xslt_keys->stylesheet_uri, stylesheet_uri) == 0)
            && (stylesheet_mtime == 0 || xslt_keys->stylesheet_mtime == stylesheet_mtime)
            && (document_uri == NULL || strcmp(xslt_keys->document_uri, document_uri) == 0)
            && (document_mtime == 0 || xslt_keys->document_mtime == document_mtime)
        )
        {

#ifdef NGX_DEBUG
            ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                               "ngx_http_xsltproc_xslt_keys_cache_expire: expired stylesheet %s, document %s",
                               xslt_keys->stylesheet_uri, xslt_keys->document_uri);
#endif

            ngx_http_xsltproc_list_remove(el);
            el = ngx_http_xsltproc_list_next(el);

            ngx_http_xsltproc_xslt_keys_free(xslt_keys, XSLT_KEYS_LIST_FREE_KEYS | XSLT_KEYS_LIST_FREE_DATA);

            break;
        } else {
            el = ngx_http_xsltproc_list_next(el);
        }
    }
}

static void
ngx_http_xsltproc_xslt_keys_cache_free(void)
{
    ngx_http_xsltproc_xslt_keys_list_free(&xslt_keys_cache, XSLT_KEYS_LIST_FREE_KEYS | XSLT_KEYS_LIST_FREE_DATA);
}

int
ngx_http_xsltproc_xslt_keys_cache_init(ngx_log_t *log)
{
    xslt_keys_cache_log = log;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                       "ngx_http_xsltproc_xslt_keys_cache_init: init");
#endif

    ngx_http_xsltproc_list_init(&xslt_keys_cache);

    return 0;
}

void
ngx_http_xsltproc_xslt_keys_cache_destroy()
{
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_cache_log, 0,
                       "ngx_http_xsltproc_xslt_keys_cache_destroy: destroy");
#endif

    ngx_http_xsltproc_xslt_keys_cache_free();
}

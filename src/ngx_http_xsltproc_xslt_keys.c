#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_log_t *xslt_keys_log = NULL;

ngx_http_xsltproc_xslt_keys_t *
ngx_http_xsltproc_xslt_keys_new(char *stylesheet_uri, time_t stylesheet_mtime,
    char *document_uri, time_t document_mtime, xsltDocumentPtr xslt_document)
{
    ngx_http_xsltproc_xslt_keys_t *xslt_keys;

    if ((xslt_keys = ngx_http_xsltproc_malloc(sizeof(ngx_http_xsltproc_xslt_keys_t))) == NULL) {
        return NULL;
    }

    memset(xslt_keys, 0, sizeof(ngx_http_xsltproc_xslt_keys_t));

    xslt_keys->stylesheet_uri   = strdup(stylesheet_uri);
    xslt_keys->stylesheet_mtime = stylesheet_mtime;
    xslt_keys->document_uri     = strdup(document_uri);
    xslt_keys->document_mtime   = document_mtime;
    xslt_keys->xslt_document    = xslt_document;

#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_keys_log, 0,
                       "ngx_http_xsltproc_xslt_keys_new: stylesheet %s %d, document %s %d",
                       stylesheet_uri, (int) stylesheet_mtime,
                       document_uri, (int) document_mtime);
#endif

    return xslt_keys;
}

int
ngx_http_xsltproc_xslt_keys_init(ngx_log_t *log)
{
    xslt_keys_log = log;

    ngx_http_xsltproc_xslt_keys_cache_init(log);

    return 0;
}

void
ngx_http_xsltproc_xslt_keys_destroy(void)
{
    ngx_http_xsltproc_xslt_keys_cache_destroy();
}

void
ngx_http_xsltproc_xslt_keys_list_free(ngx_http_xsltproc_list_t *xslt_keys_list, int type)
{
    ngx_http_xsltproc_list_t      *el;
    ngx_http_xsltproc_xslt_keys_t *xslt_keys;

    for ( ;; ) {
        if (ngx_http_xsltproc_list_empty(xslt_keys_list))
            break;

        el = ngx_http_xsltproc_list_last(xslt_keys_list);
        ngx_http_xsltproc_list_remove(el);

        xslt_keys = (ngx_http_xsltproc_xslt_keys_t *) el;

        ngx_http_xsltproc_xslt_keys_free(xslt_keys, type);
    }
}

void
ngx_http_xsltproc_xslt_keys_free(ngx_http_xsltproc_xslt_keys_t *xslt_keys, int type)
{
    if (type & XSLT_KEYS_LIST_FREE_KEYS)
        xsltFreeDocumentKeys(xslt_keys->xslt_document);

    if (type & XSLT_KEYS_LIST_FREE_DATA) {
        ngx_http_xsltproc_free(xslt_keys->xslt_document);
        ngx_http_xsltproc_free(xslt_keys->stylesheet_uri);
        ngx_http_xsltproc_free(xslt_keys->document_uri);
    }

    ngx_http_xsltproc_free(xslt_keys);
}

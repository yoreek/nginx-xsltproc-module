#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_http_xsltproc_list_t xslt_document_cache;
static ngx_log_t *xslt_document_cache_log = NULL;

ngx_http_xsltproc_xslt_document_t *ngx_http_xsltproc_xslt_document_cache_lookup(char *uri) {
    ngx_http_xsltproc_xslt_document_t           *xslt_document = NULL;
    ngx_http_xsltproc_list_t                    *el;
    ngx_http_xsltproc_xml_document_extra_info_t *doc_extra_info;
    xmlDocPtr                                    doc;
    int                                          found = 0;

    for (
        el = ngx_http_xsltproc_list_first(&xslt_document_cache);
        el != ngx_http_xsltproc_list_end(&xslt_document_cache);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        xslt_document = (ngx_http_xsltproc_xslt_document_t *) el;

        if (strcmp(xslt_document->uri, uri) == 0) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_cache_log, 0,
                       "ngx_http_xsltproc_xslt_document_cache_lookup: document %s is found in cache",
                       uri);
#endif
            found = 1;

            break;
        }
    }

    if (found && ngx_http_xsltproc_xslt_document_is_updated(xslt_document)) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_cache_log, 0,
                       "ngx_http_xsltproc_xslt_document_cache_looku: document %s is expired",
                       xslt_document->uri);
#endif
        doc               = xslt_document->doc;
        doc_extra_info    = doc->_private;

        ngx_http_xsltproc_xslt_keys_cache_expire(NULL, 0, xslt_document->uri, doc_extra_info->mtime);

        ngx_http_xsltproc_xslt_document_clear(xslt_document);
    }

    if (!found) {
        xslt_document = ngx_http_xsltproc_xslt_document_new(uri);
        ngx_http_xsltproc_list_insert_tail(&xslt_document_cache, (ngx_http_xsltproc_list_t *) xslt_document);
    }

    return xslt_document;
}

static void ngx_http_xsltproc_xslt_document_cache_free(void) {
    ngx_http_xsltproc_list_t *el;
    for (
        el = ngx_http_xsltproc_list_first(&xslt_document_cache);
        el != ngx_http_xsltproc_list_end(&xslt_document_cache);
        el = ngx_http_xsltproc_list_next(el)
    ) {
        ngx_http_xsltproc_xslt_document_free((ngx_http_xsltproc_xslt_document_t *) el);
    }
}

int ngx_http_xsltproc_xslt_document_cache_init(ngx_log_t *log) {
    xslt_document_cache_log = log;

    ngx_http_xsltproc_list_init(&xslt_document_cache);

    return 0;
}

void ngx_http_xsltproc_xslt_document_cache_destroy(void) {
	ngx_http_xsltproc_xslt_document_cache_free();
}

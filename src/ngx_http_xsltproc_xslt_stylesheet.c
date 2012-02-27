#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static ngx_log_t *xslt_stylesheet_log = NULL;

ngx_http_xsltproc_xslt_stylesheet_t *ngx_http_xsltproc_xslt_stylesheet_new(char *uri) {
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;

    if ((xslt_stylesheet = ngx_http_xsltproc_malloc(sizeof(ngx_http_xsltproc_xslt_stylesheet_t))) == NULL) {
        return NULL;
    }

    memset(xslt_stylesheet, 0, sizeof(ngx_http_xsltproc_xslt_stylesheet_t));

    xslt_stylesheet->uri   = strdup(uri);
    xslt_stylesheet->mtime = time(NULL);

    return xslt_stylesheet;
}

ngx_http_xsltproc_xslt_stylesheet_t *
ngx_http_xsltproc_xslt_stylesheet_parse_file(ngx_http_xsltproc_filter_loc_conf_t *cf, char *uri) {
    ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet;

    if (cf->stylesheet_caching == 1) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                           "ngx_http_xsltproc_xslt_stylesheet_parse_file: cache lookup \"%s\"",
                           uri);
#endif

        xslt_stylesheet = ngx_http_xsltproc_xslt_stylesheet_cache_lookup(cf, uri);
    }
    else {
        xslt_stylesheet = ngx_http_xsltproc_xslt_stylesheet_new(uri);
    }

    if (xslt_stylesheet != NULL && xslt_stylesheet->stylesheet == NULL) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                           "ngx_http_xsltproc_xslt_stylesheet_parse_file: parse stylesheet \"%s\"",
                           uri);
#endif

        xslt_stylesheet->stylesheet = xsltParseStylesheetFile((const xmlChar *) uri);

        if (xslt_stylesheet->stylesheet == NULL) {
            xslt_stylesheet = NULL;
        }
    }

    return xslt_stylesheet;
}

int ngx_http_xsltproc_xslt_stylesheet_init(ngx_log_t *log) {
    xslt_stylesheet_log = log;

    ngx_http_xsltproc_xslt_stylesheet_cache_init(log);

    return 0;
}

void ngx_http_xsltproc_xslt_stylesheet_destroy(void) {
    ngx_http_xsltproc_xslt_stylesheet_cache_destroy();
}

void ngx_http_xsltproc_xslt_stylesheet_free_documents(xsltDocumentPtr doc_list) {
    xsltDocumentPtr doc;

    while (doc_list != NULL) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                           "ngx_http_xsltproc_xslt_stylesheet_free_documents: document %s",
                           doc_list->doc->URL);
#endif

        doc      = doc_list;
        doc_list = doc_list->next;

        xsltFreeDocumentKeys(doc);
        xmlFree(doc);
    }
}

void ngx_http_xsltproc_xslt_stylesheet_free(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet) {
    ngx_http_xsltproc_xslt_stylesheet_clear(xslt_stylesheet);

    ngx_http_xsltproc_free(xslt_stylesheet->uri);
    ngx_http_xsltproc_free(xslt_stylesheet);
}

void ngx_http_xsltproc_xslt_stylesheet_clear(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet) {
    if (xslt_stylesheet->stylesheet != NULL) {
        if (xslt_stylesheet->stylesheet->doc != NULL) {
#ifdef NGX_DEBUG
            ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                               "ngx_http_xsltproc_xslt_stylesheet_clear: _private %s",
                               xslt_stylesheet->uri);
#endif

            ngx_http_xsltproc_free(xslt_stylesheet->stylesheet->doc->_private);
        }

#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                           "ngx_http_xsltproc_xslt_stylesheet_clear: stylesheet %s",
                           xslt_stylesheet->uri);
#endif

        xsltFreeStylesheet(xslt_stylesheet->stylesheet);

        xslt_stylesheet->stylesheet = NULL;
    }

    ngx_http_xsltproc_xslt_stylesheet_free_documents(xslt_stylesheet->doc_list);
}

int ngx_http_xsltproc_xslt_stylesheet_is_updated(ngx_http_xsltproc_xslt_stylesheet_t *xslt_stylesheet) {
    xsltStylesheetPtr                            stylesheet;
    xmlDocPtr                                    doc;
    ngx_http_xsltproc_xml_document_extra_info_t *doc_extra_info;

    stylesheet = xslt_stylesheet->stylesheet;
    while (stylesheet != NULL) {
        doc            = stylesheet->doc;
        doc_extra_info = doc->_private;

        if (doc_extra_info->mtime != ngx_http_xsltproc_last_modify((const char *) doc->URL)) {
#ifdef NGX_DEBUG
            ngx_log_error_core(NGX_LOG_DEBUG, xslt_stylesheet_log, 0,
                               "ngx_http_xsltproc_xslt_stylesheet_is_updated: stylesheet is updated: %s mtime_old: %d mtime: %d",
                               (const char *) doc->URL, (int) doc_extra_info->mtime,
                               (int) ngx_http_xsltproc_last_modify((const char *) doc->URL));
#endif

            return 1;
        }

        if (stylesheet->imports != NULL) {
            stylesheet = stylesheet->imports;
        } else if (stylesheet->next != NULL) {
            stylesheet = stylesheet->next;
        } else {
            while ((stylesheet = stylesheet->parent) != NULL) {
                if (stylesheet->next != NULL) {
                    stylesheet = stylesheet->next;
                    break;
                }
            }
        }
    }
    return 0;
}

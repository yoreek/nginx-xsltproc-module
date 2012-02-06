#include "ngx_http_xsltproc_core.h"
#include "ngx_http_xsltproc_xslt.h"

static xsltDocLoaderFunc xslt_document_loader_func_original = NULL;
static ngx_log_t *xslt_document_log = NULL;

ngx_http_xsltproc_xslt_document_t *ngx_http_xsltproc_xslt_document_new(char *uri) {
    ngx_http_xsltproc_xslt_document_t *xslt_document;

    if ((xslt_document = ngx_http_xsltproc_malloc(sizeof(ngx_http_xsltproc_xslt_document_t))) == NULL) {
        return NULL;
    }

    memset(xslt_document, 0, sizeof(ngx_http_xsltproc_xslt_document_t));

    xslt_document->uri = strdup(uri);

    return xslt_document;
}

static xmlDocPtr
ngx_http_xsltproc_xslt_document_load(const xmlChar * URI, xmlDictPtr dict, int options,
                              void *ctxt ATTRIBUTE_UNUSED,
                              xsltLoadType type ATTRIBUTE_UNUSED)
{
    xmlDocPtr doc;
    ngx_http_xsltproc_xml_document_extra_info_t *doc_extra_info;
    if ((doc_extra_info = ngx_http_xsltproc_malloc(sizeof(ngx_http_xsltproc_xml_document_extra_info_t))) == NULL)
        return NULL;

    doc = xslt_document_loader_func_original(URI, dict, options, ctxt, type);
    if (doc == NULL)
        return NULL;

    doc->_private = doc_extra_info;
    doc_extra_info->mtime = ngx_http_xsltproc_last_modify((const char *) doc->URL);

    return doc;
}

static xmlDocPtr
ngx_http_xsltproc_xslt_document_loader_func(const xmlChar * URI, xmlDictPtr dict, int options,
    void *ctxt ATTRIBUTE_UNUSED, xsltLoadType type ATTRIBUTE_UNUSED)
{
    ngx_http_xsltproc_xslt_document_t *xslt_document;
    char *uri = (char *) URI;

#ifdef NGX_DEBUG
    ngx_log_error(NGX_LOG_NOTICE, xslt_document_log, 0,
                  "ngx_http_xsltproc_xslt_document_loader_func: load document: %s",
                  uri);
#endif

    /* !!! don't cache stylesheets */
    if (type == XSLT_LOAD_STYLESHEET || type == XSLT_LOAD_START) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_log, 0,
                           "ngx_http_xsltproc_xslt_document_loader_func: don't cache document: %s",
                           URI);
#endif

        return ngx_http_xsltproc_xslt_document_load(URI, dict, options, ctxt, type);
    }

    xslt_document = ngx_http_xsltproc_xslt_document_cache_lookup(uri);

    if (xslt_document != NULL && xslt_document->doc == NULL) {
#ifdef NGX_DEBUG
        ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_log, 0,
                           "ngx_http_xsltproc_xslt_document_loader_func: parse document %s",
                           uri);
#endif

        xslt_document->doc = ngx_http_xsltproc_xslt_document_load(URI, dict, options, ctxt, type);

        if (xslt_document->doc == NULL) {
#ifdef NGX_DEBUG
            ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_log, 0,
                               "ngx_http_xsltproc_xslt_document_loader_func: document %s is not parsed",
                               uri);
#endif

            xslt_document = NULL;
        }
    }

    if (xslt_document == NULL)
        return NULL;

    return xslt_document->doc;
}

int ngx_http_xsltproc_xslt_document_init(ngx_log_t *log) {
    xslt_document_log = log;

    ngx_http_xsltproc_xslt_document_cache_init(log);

    xslt_document_loader_func_original = xsltDocDefaultLoader;
    xsltSetLoaderFunc(ngx_http_xsltproc_xslt_document_loader_func);

    return 0;
}

void ngx_http_xsltproc_xslt_document_destroy(void) {
    xsltSetLoaderFunc(xslt_document_loader_func_original);

    ngx_http_xsltproc_xslt_document_cache_destroy();
}

void ngx_http_xsltproc_xslt_document_free(ngx_http_xsltproc_xslt_document_t *xslt_document) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_log, 0,
                       "ngx_http_xsltproc_xslt_document_free: document %s",
                       xslt_document->uri);
#endif

    ngx_http_xsltproc_xslt_document_clear(xslt_document);

    ngx_http_xsltproc_free(xslt_document->uri);
    ngx_http_xsltproc_free(xslt_document);
}

void ngx_http_xsltproc_xslt_document_clear(ngx_http_xsltproc_xslt_document_t *xslt_document) {
#ifdef NGX_DEBUG
    ngx_log_error_core(NGX_LOG_DEBUG, xslt_document_log, 0,
                       "ngx_http_xsltproc_xslt_document_clear: document %s",
                       xslt_document->uri);
#endif

    if (xslt_document->doc != NULL) {
        ngx_http_xsltproc_free(xslt_document->doc->_private);
        xmlFreeDoc(xslt_document->doc);

        xslt_document->doc = NULL;
    }
}

int ngx_http_xsltproc_xslt_document_is_updated(ngx_http_xsltproc_xslt_document_t *xslt_document) {
    xmlDocPtr                                    doc;
    ngx_http_xsltproc_xml_document_extra_info_t *doc_extra_info;

    doc            = xslt_document->doc;
    doc_extra_info = doc->_private;

    if (doc_extra_info->mtime != ngx_http_xsltproc_last_modify((const char *) doc->URL)) {
#ifdef NGX_DEBUG
    ngx_log_error(NGX_LOG_NOTICE, xslt_document_log, 0,
                  "ngx_http_xsltproc_xslt_document_is_updated: document is updated: %s mtime_old: %d mtime: %d",
                  (const char *) doc->URL, (int) doc_extra_info->mtime,
                  (int) ngx_http_xsltproc_last_modify((const char *) doc->URL));
#endif
        return 1;
    }

    return 0;
}
